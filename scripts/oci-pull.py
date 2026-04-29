#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pull an OCI image from a v2 registry and apply layers to a directory.

Usage:
    oci-pull.py pull  --image=docker://IMAGE[:TAG|@sha256:DIGEST]
                      --output=DIR [--arch=x86_64|aarch64] [--no-cache]
    oci-pull.py prune [--keep-bytes=N]

Stdlib only. Supports Docker Hub and any registry implementing the
distribution v2 spec with bearer-token auth.

Layer blobs are cached at $XDG_CACHE_HOME/kbox/oci-layers (default
~/.cache/kbox/oci-layers), keyed by sha256 digest. Cache reads are
verified by re-hashing; corrupted entries are dropped and re-fetched.

Mutable tags (e.g. 'latest', '3.21') are resolved on every pull. For
reproducible builds, pin to a digest: docker://alpine@sha256:...
"""

import argparse
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request


ACCEPT = ", ".join([
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
])

DEFAULT_REGISTRY = "registry-1.docker.io"
HTTP_TIMEOUT = 60

# DoS caps. Manifests are bounded by registry spec; blobs and tar member counts
# are sized for typical Linux images (Debian: ~50K inodes, multi-GB total).
MAX_MANIFEST_BYTES = 4 << 20            # 4 MB
MAX_BLOB_BYTES = 8 << 30                # 8 GB
MAX_TAR_MEMBERS = 500_000

ARCH_MAP = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


class _StripAuthOnCrossHost(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None
        # Compare netloc (host:port), not just hostname, so a redirect to a
        # different port on the same host still strips the bearer token.
        if urllib.parse.urlparse(req.full_url).netloc != \
                urllib.parse.urlparse(newurl).netloc:
            new_req.headers.pop("Authorization", None)
        return new_req


_OPENER = urllib.request.build_opener(_StripAuthOnCrossHost())


def _read_bounded(resp, max_bytes, what):
    """Read up to max_bytes from a response. Exit on overflow."""
    out = bytearray()
    while True:
        chunk = resp.read(1 << 16)
        if not chunk:
            return bytes(out)
        if len(out) + len(chunk) > max_bytes:
            sys.exit(f"error: {what} exceeds {max_bytes} bytes")
        out.extend(chunk)


def parse_image_ref(spec):
    """Parse 'docker://[REGISTRY/]REPO[:TAG][@DIGEST]' into (registry, repo, ref).

    'ref' is the digest if @DIGEST is present, otherwise the tag (default 'latest').
    """
    if not spec.startswith("docker://"):
        sys.exit(f"error: image must start with 'docker://': {spec}")
    rest = spec[len("docker://"):]

    digest = None
    if "@" in rest:
        rest, digest = rest.rsplit("@", 1)

    # Tag is the trailing ':TAG' on the LAST path component (so a host:port
    # registry like reg.example:5000/foo is not mis-parsed as repo=reg.example).
    last_slash = rest.rfind("/")
    last_part = rest[last_slash + 1:] if last_slash >= 0 else rest
    tag = "latest"
    if ":" in last_part:
        last_part, tag = last_part.rsplit(":", 1)
        rest = (rest[:last_slash + 1] + last_part) if last_slash >= 0 else last_part

    first_slash = rest.find("/")
    if first_slash >= 0:
        head = rest[:first_slash]
        if "." in head or ":" in head or head == "localhost":
            registry, repo = head, rest[first_slash + 1:]
        else:
            registry, repo = DEFAULT_REGISTRY, rest
    else:
        registry, repo = DEFAULT_REGISTRY, "library/" + rest

    return registry, repo, digest if digest else tag


class Client:
    def __init__(self, registry):
        self.registry = registry
        self.token = None

    def _open(self, url, accept):
        headers = {"Accept": accept}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return _OPENER.open(urllib.request.Request(url, headers=headers),
                            timeout=HTTP_TIMEOUT)

    def _refresh_token(self, www_auth):
        m = re.match(r"Bearer\s+(.*)", www_auth or "")
        if not m:
            sys.exit(f"error: unsupported WWW-Authenticate: {www_auth!r}")
        params = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
        realm = params.pop("realm", None)
        if not realm:
            sys.exit(f"error: WWW-Authenticate missing realm: {www_auth!r}")
        url = realm + ("?" + urllib.parse.urlencode(params) if params else "")
        with _OPENER.open(url, timeout=HTTP_TIMEOUT) as r:
            body = json.loads(_read_bounded(r, MAX_MANIFEST_BYTES, "auth token"))
        self.token = body.get("token") or body.get("access_token")
        if not self.token:
            sys.exit("error: token endpoint returned no token")

    def fetch(self, url, accept):
        try:
            resp = self._open(url, accept)
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise
            self._refresh_token(e.headers.get("WWW-Authenticate"))
            resp = self._open(url, accept)
        return _read_bounded(resp, MAX_MANIFEST_BYTES, "manifest/index")

    def open_stream(self, url, accept):
        try:
            return self._open(url, accept)
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise
            self._refresh_token(e.headers.get("WWW-Authenticate"))
            return self._open(url, accept)

    def manifest_url(self, repo, ref):
        return f"https://{self.registry}/v2/{repo}/manifests/{ref}"

    def blob_url(self, repo, digest):
        return f"https://{self.registry}/v2/{repo}/blobs/{digest}"


def select_manifest(index, oci_arch):
    """From a manifest list / OCI index, pick the linux/<arch> entry."""
    candidates = [d for d in index.get("manifests", [])
                  if d.get("platform", {}).get("os") == "linux"
                  and d.get("platform", {}).get("architecture") == oci_arch]
    if not candidates:
        sys.exit(f"error: no linux/{oci_arch} manifest in index")
    no_variant = [d for d in candidates if "variant" not in d.get("platform", {})]
    return (no_variant or candidates)[0]


def cache_root():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "kbox", "oci-layers")


def cache_path_for(digest):
    return os.path.join(cache_root(), digest.replace(":", "_"))


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def stream_blob(client, repo, digest, dest_path, declared_size=None):
    """Stream a blob into dest_path, verifying its sha256 digest in flight.

    If declared_size is provided (from the layer descriptor), reject early when
    the advertised size exceeds MAX_BLOB_BYTES; the streaming loop also caps the
    actual bytes received in case the registry advertises one size and serves
    another.
    """
    if not digest.startswith("sha256:"):
        sys.exit(f"error: unsupported digest algorithm: {digest}")
    if declared_size is not None and declared_size > MAX_BLOB_BYTES:
        sys.exit(f"error: layer {digest} declared size {declared_size} "
                 f"exceeds cap {MAX_BLOB_BYTES}")
    expected = digest.split(":", 1)[1]
    h = hashlib.sha256()
    resp = client.open_stream(client.blob_url(repo, digest),
                              "application/octet-stream")
    received = 0
    with open(dest_path, "wb") as out:
        while True:
            chunk = resp.read(1 << 16)
            if not chunk:
                break
            received += len(chunk)
            if received > MAX_BLOB_BYTES:
                os.unlink(dest_path)
                sys.exit(f"error: layer {digest} streamed past cap "
                         f"{MAX_BLOB_BYTES}")
            h.update(chunk)
            out.write(chunk)
    if h.hexdigest() != expected:
        os.unlink(dest_path)
        sys.exit(f"error: digest mismatch for {digest}: got sha256:{h.hexdigest()}")


def fetch_blob(client, repo, digest, declared_size=None, use_cache=True):
    """Return a path to the verified blob. Cached if available, else downloaded."""
    if use_cache:
        cached = cache_path_for(digest)
        if os.path.isfile(cached):
            expected = digest.split(":", 1)[1]
            if hash_file(cached) == expected:
                print(f"    cache hit ({cached})", file=sys.stderr)
                return cached, False
            print(f"    cache corrupt, re-fetching ({cached})", file=sys.stderr)
            os.unlink(cached)

        os.makedirs(cache_root(), exist_ok=True)
        # mkstemp gives a unique name in the same dir, so os.replace is atomic
        # and concurrent writers don't collide on a PID-based name.
        fd, tmp = tempfile.mkstemp(
            prefix=os.path.basename(cached) + ".", suffix=".tmp",
            dir=cache_root())
        os.close(fd)
        try:
            stream_blob(client, repo, digest, tmp, declared_size)
            os.replace(tmp, cached)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return cached, True

    # No-cache path: stream into a fresh temp file the caller will discard.
    fd, tmp = tempfile.mkstemp(prefix="kbox-oci-")
    os.close(fd)
    try:
        stream_blob(client, repo, digest, tmp, declared_size)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return tmp, True


def safe_join(root, name):
    """Resolve a tar member path against root, rejecting absolute and traversal."""
    while name.startswith(("./", "/")):
        name = name[2:] if name.startswith("./") else name[1:]
    if not name:
        return None
    if any(p == ".." for p in name.split("/")):
        return None
    return os.path.join(root, name)


def resolve_hardlink(root, member_name, linkname):
    """Resolve a tar hardlink target. Per POSIX/GNU tar, linkname is the
    archive-member name (root-relative). Some tarballs in the wild also use
    parent-relative linknames; we accept those if they normalize to a path
    inside the archive, but only after re-validating through safe_join (so
    `..` traversal and absolute targets stay rejected).
    """
    candidates = []

    direct = safe_join(root, linkname)
    if direct is not None:
        candidates.append(direct)

    # Parent-relative interpretation. posixpath.join discards earlier
    # components when linkname is absolute, so we must reject that here --
    # otherwise an absolute linkname (e.g. "/etc/passwd") would resolve to
    # a host path, escaping rootfs.
    if not posixpath.isabs(linkname):
        relative = posixpath.normpath(
            posixpath.join(posixpath.dirname(member_name), linkname))
        if (relative not in ("", ".")
                and relative != ".."
                and not relative.startswith("../")):
            rel_path = safe_join(root, relative)
            if rel_path is not None and rel_path not in candidates:
                candidates.append(rel_path)

    if not candidates:
        return None
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[0]


def _under_rootfs(rootfs_real, path):
    """True if path resolves (via realpath) to a location inside rootfs_real.

    Defends against a layer creating an in-staging symlink (e.g. etc -> /etc)
    and a later member writing through it. realpath() resolves any symlinked
    parent components; non-existent leaf components remain literal.
    """
    real = os.path.realpath(path)
    return real == rootfs_real or real.startswith(rootfs_real + os.sep)


def _record_ownership(ownership, path, info):
    """Insert/update an ownership entry, pushing it to the END of the dict.

    Manifest emission iterates the dict in insertion order, and the C helper
    rewrites inodes by path. With hardlinks, two paths share one inode -- so
    a stale sibling entry would overwrite a newer chmod on the same inode if
    the dict still iterated in original-insertion order. pop+reinsert pushes
    the most-recently-modified path last, so "last metadata op wins" on the
    inode.
    """
    if ownership is None:
        return
    ownership.pop(path, None)
    ownership[path] = info


def _unlink_leaf_if_nondir(path):
    """Remove an existing non-directory leaf without following symlinks."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        return
    os.unlink(path)


def _ensure_parent_dirs(rootfs, path, ownership, _uid=None, _gid=None):
    """Create missing parent dirs as 0:0:0755 (FHS default for system dirs).

    Synthetic parents only fire on malformed archives that omit explicit
    parent entries -- well-formed OCI layers include them in tree order, so
    `lexists` short-circuits here. Defaulting to root-owned avoids leaking a
    daemon UID (e.g. postgres) onto an ancestor when the child's uid/gid is
    a non-root user. If a real layer member later targets the same path,
    _record_ownership pop+reinserts so the explicit metadata wins.
    """
    rel_parent = os.path.relpath(os.path.dirname(path), rootfs)
    if rel_parent == ".":
        return
    current = rootfs
    for part in rel_parent.split(os.sep):
        current = os.path.join(current, part)
        if os.path.lexists(current):
            continue
        os.mkdir(current, 0o755)
        _record_ownership(ownership,
                          os.path.relpath(current, rootfs),
                          (0, 0, 0o755))


def apply_layer(tar_path, rootfs, ownership=None):
    """Apply one OCI layer tarball to rootfs. Handles whiteouts and links.

    If `ownership` is a dict, records {path: (uid, gid, mode)} for each
    file/dir/hardlink. Whiteouts erase entries; later layers override.
    Symlinks and device nodes are excluded (rootless cannot mknod, and
    lchown semantics aren't useful for our threat model).
    """
    skipped_devnodes = 0
    rootfs_real = os.path.realpath(rootfs)
    members_seen = 0
    with tarfile.open(tar_path, mode="r:*") as tf:
        for member in tf:
            members_seen += 1
            if members_seen > MAX_TAR_MEMBERS:
                sys.exit(f"error: tar member count exceeds {MAX_TAR_MEMBERS} "
                         "(possible tar bomb)")
            dest = safe_join(rootfs, member.name)
            if dest is None:
                print(f"  skip unsafe path: {member.name!r}", file=sys.stderr)
                continue
            base = os.path.basename(dest)

            # Symlink-traversal guard. Check the parent (the leaf may not yet
            # exist, and may itself be a symlink we're about to overwrite).
            if not _under_rootfs(rootfs_real, os.path.dirname(dest)):
                print(f"  skip symlink-escape parent for {member.name!r}",
                      file=sys.stderr)
                continue

            if base == ".wh..wh..opq":
                parent = os.path.dirname(dest)
                if os.path.isdir(parent) and not os.path.islink(parent):
                    for entry in os.listdir(parent):
                        ep = os.path.join(parent, entry)
                        if os.path.islink(ep) or not os.path.isdir(ep):
                            os.unlink(ep)
                        else:
                            shutil.rmtree(ep, ignore_errors=True)
                if ownership is not None:
                    rel = os.path.relpath(parent, rootfs)
                    prefix = (rel + os.sep) if rel != "." else ""
                    for k in [k for k in ownership
                              if k != "." and k.startswith(prefix)]:
                        del ownership[k]
                continue

            if base.startswith(".wh."):
                target = os.path.join(os.path.dirname(dest), base[len(".wh."):])
                if os.path.islink(target) or os.path.isfile(target):
                    os.unlink(target)
                elif os.path.isdir(target):
                    shutil.rmtree(target, ignore_errors=True)
                if ownership is not None:
                    rel = os.path.relpath(target, rootfs)
                    prefix = rel + os.sep
                    ownership.pop(rel, None)
                    for k in [k for k in ownership if k.startswith(prefix)]:
                        del ownership[k]
                continue

            mode = member.mode & 0o7777
            uid = member.uid
            gid = member.gid
            try:
                if member.isdir():
                    _ensure_parent_dirs(rootfs, dest, ownership, uid, gid)
                    # Replace any pre-existing symlink at dest before
                    # makedirs/chmod, otherwise a malicious prior-layer
                    # symlink would redirect chmod onto the host directory.
                    if os.path.lexists(dest) and os.path.islink(dest):
                        os.unlink(dest)
                    os.makedirs(dest, exist_ok=True)
                    os.chmod(dest, mode)
                    _record_ownership(ownership,
                                      os.path.relpath(dest, rootfs),
                                      (uid, gid, mode))
                elif member.issym():
                    _ensure_parent_dirs(rootfs, dest, ownership, uid, gid)
                    if os.path.lexists(dest):
                        os.unlink(dest)
                    os.symlink(member.linkname, dest)
                elif member.islnk():
                    link_dest = resolve_hardlink(rootfs, member.name,
                                                 member.linkname)
                    if link_dest is None:
                        print(f"  skip unsafe hardlink: {member.linkname!r}",
                              file=sys.stderr)
                        continue
                    # Realpath-confine the source: a previously-extracted
                    # symlink in the staging tree could otherwise redirect
                    # to a host path, and Python's os.link follows symlinks
                    # via linkat(AT_SYMLINK_FOLLOW) by default. We also pass
                    # follow_symlinks=False below as defense in depth.
                    if not _under_rootfs(rootfs_real, link_dest):
                        print(f"  skip symlink-escape hardlink source for "
                              f"{member.name!r}", file=sys.stderr)
                        continue
                    if not os.path.exists(link_dest):
                        # Forward-reference: tarfile cannot resolve a hardlink
                        # whose target appears later in the archive (it only
                        # searches earlier members). OCI layers in practice
                        # always reference earlier members, so warn and skip.
                        print(f"  warning: hardlink {member.name!r} -> "
                              f"{member.linkname!r}: target not yet extracted",
                              file=sys.stderr)
                        continue
                    _ensure_parent_dirs(rootfs, dest, ownership, uid, gid)
                    if os.path.lexists(dest):
                        os.unlink(dest)
                    os.link(link_dest, dest, follow_symlinks=False)
                    _record_ownership(ownership,
                                      os.path.relpath(dest, rootfs),
                                      (uid, gid, mode))
                elif member.isfile():
                    _ensure_parent_dirs(rootfs, dest, ownership, uid, gid)
                    fobj = tf.extractfile(member)
                    if fobj is not None:
                        _unlink_leaf_if_nondir(dest)
                        # Open with O_NOFOLLOW so a malicious pre-existing
                        # symlink at dest cannot redirect the write.
                        flags = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                                 | os.O_NOFOLLOW)
                        fd = os.open(dest, flags, mode)
                        try:
                            with os.fdopen(fd, "wb") as out:
                                shutil.copyfileobj(fobj, out)
                        finally:
                            try:
                                os.chmod(dest, mode)
                            except OSError:
                                pass
                        _record_ownership(ownership,
                                          os.path.relpath(dest, rootfs),
                                          (uid, gid, mode))
                elif member.ischr() or member.isblk() or member.isfifo():
                    # Rootless cannot mknod; /dev is mounted at guest runtime.
                    skipped_devnodes += 1
            except OSError as exc:
                print(f"  warning: {member.name}: {exc}", file=sys.stderr)
    if skipped_devnodes:
        print(f"  skipped {skipped_devnodes} device/fifo node(s) "
              "(rootless cannot mknod; /dev is a runtime mount)",
              file=sys.stderr)


def is_index(manifest):
    media = manifest.get("mediaType", "")
    if "manifest.list" in media or "image.index" in media:
        return True
    return "manifests" in manifest and "layers" not in manifest


def pull(image_url, output_dir, arch, use_cache=True, manifest_path=None):
    oci_arch = ARCH_MAP.get(arch)
    if not oci_arch:
        sys.exit(f"error: unsupported arch: {arch}")

    registry, repo, ref = parse_image_ref(image_url)
    print(f"pulling {registry}/{repo}:{ref} ({oci_arch})", file=sys.stderr)

    client = Client(registry)
    manifest = json.loads(client.fetch(client.manifest_url(repo, ref), ACCEPT))

    if is_index(manifest):
        desc = select_manifest(manifest, oci_arch)
        print(f"  selected {desc['digest'][:19]}...", file=sys.stderr)
        manifest = json.loads(client.fetch(client.manifest_url(repo, desc["digest"]),
                                           ACCEPT))

    layers = manifest.get("layers", [])
    if not layers:
        sys.exit("error: manifest has no layers")

    os.makedirs(output_dir, exist_ok=True)
    ownership = {} if manifest_path else None
    if ownership is not None:
        # OCI layers rarely carry an explicit "/" entry, but the root inode
        # still needs deterministic uid/gid/mode when mkrootfs rewrites it.
        _record_ownership(ownership, ".", (0, 0, 0o755))
    for i, layer in enumerate(layers):
        digest = layer["digest"]
        declared_size = layer.get("size")
        print(f"  layer {i + 1}/{len(layers)}: {digest[:19]}...",
              file=sys.stderr)
        blob_path, ephemeral = fetch_blob(client, repo, digest,
                                          declared_size, use_cache)
        try:
            apply_layer(blob_path, output_dir, ownership)
        finally:
            if ephemeral and not use_cache:
                # No-cache: we wrote to a tempfile; clean it up.
                try:
                    os.unlink(blob_path)
                except OSError:
                    pass

    if manifest_path is not None:
        # NUL-separated records: <uid>\t<gid>\t<mode>\t<path>\0
        # The root inode is emitted as path ".".
        with open(manifest_path, "wb") as f:
            for path, (uid, gid, mode) in ownership.items():
                rec = f"{uid}\t{gid}\t{mode:o}\t{path}\0"
                f.write(rec.encode("utf-8", "surrogateescape"))
        print(f"  wrote ownership manifest: {manifest_path} "
              f"({len(ownership)} entries)", file=sys.stderr)

    print("done", file=sys.stderr)


def prune(keep_bytes=0):
    """Remove cached layer blobs. With keep_bytes>0, keep newest blobs up to budget."""
    root = cache_root()
    if not os.path.isdir(root):
        print(f"cache empty: {root}", file=sys.stderr)
        return

    entries = []
    for name in os.listdir(root):
        full = os.path.join(root, name)
        try:
            st = os.stat(full)
        except OSError:
            continue
        if not os.path.isfile(full):
            continue
        entries.append((st.st_mtime, st.st_size, full))

    if keep_bytes > 0:
        # Keep newest first; evict from the oldest end until under budget.
        entries.sort(reverse=True)
        running = 0
        keep_count = 0
        for mtime, size, full in entries:
            if running + size <= keep_bytes:
                running += size
                keep_count += 1
            else:
                break
        evict = entries[keep_count:]
    else:
        evict = entries

    total = 0
    for _, size, full in evict:
        try:
            os.unlink(full)
            total += size
        except OSError as exc:
            print(f"  warning: {full}: {exc}", file=sys.stderr)
    print(f"pruned {len(evict)} blob(s), {total} bytes from {root}",
          file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("pull", help="pull an image into a directory")
    pp.add_argument("--image", required=True,
                    help="docker://[REGISTRY/]REPO[:TAG][@sha256:DIGEST]")
    pp.add_argument("--output", required=True,
                    help="staging directory to populate")
    pp.add_argument("--arch", default=os.uname().machine,
                    help="kbox arch (x86_64 or aarch64); default: host arch")
    pp.add_argument("--no-cache", action="store_true",
                    help="bypass the layer cache (don't read or write)")
    pp.add_argument("--manifest", default=None,
                    help="emit a uid/gid/mode manifest for tools/oci-chown")

    pr = sub.add_parser("prune", help="remove cached layer blobs")
    pr.add_argument("--keep-bytes", type=int, default=0,
                    help="keep newest blobs up to this many bytes (default: 0 = wipe)")

    args = p.parse_args()
    if args.cmd == "pull":
        pull(args.image, args.output, args.arch,
             use_cache=not args.no_cache, manifest_path=args.manifest)
    else:
        prune(args.keep_bytes)


if __name__ == "__main__":
    main()

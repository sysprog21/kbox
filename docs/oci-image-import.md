# OCI image import

`kbox` can build a rootfs from any OCI image hosted on a Docker
[v2 registry](https://distribution.github.io/distribution/spec/api/),
not just the bundled Alpine minirootfs. Pass `--image=docker://...` to
[`scripts/mkrootfs.sh`](../scripts/mkrootfs.sh) and the script pulls the
image's manifest and layer blobs, applies them to a staging directory,
and feeds the result into `mke2fs -d` exactly like the Alpine path.

The implementation is rootless and depends only on `python3` (stdlib
only) and `e2fsprogs` (already required for `mke2fs`). The optional
`--rewrite-uid` flag adds an in-tree libext2fs helper
([`tools/oci-chown`](../tools/oci-chown/)) for restoring OCI tar-header
uid/gid/mode into ext4 inodes; it is built on demand and only required
when the rootfs will be used with `kbox --root-id`.

## Quick start

```bash
# Pull and build a rootfs from Docker Hub.
ROOTFS=alpine.ext4 ./scripts/mkrootfs.sh --image=docker://alpine:3.21

# Pin to a digest for reproducibility.
ROOTFS=alpine.ext4 ./scripts/mkrootfs.sh \
    --image=docker://alpine@sha256:1832327faf04...

# Other registries (host:port supported).
ROOTFS=node.ext4 ./scripts/mkrootfs.sh \
    --image=docker://node:alpine --size=512

# Restore OCI tar-header uid/gid/mode (required for --root-id).
ROOTFS=node.ext4 ./scripts/mkrootfs.sh \
    --image=docker://node:alpine --rewrite-uid

# Run with kbox.
./kbox -S node.ext4 --root-id -- /usr/bin/node --version

# Manage the layer cache.
python3 ./scripts/oci-pull.py prune                  # wipe
python3 ./scripts/oci-pull.py prune --keep-bytes=2G  # keep newest 2 GB
```

`--image` accepts:

- `docker://NAME[:TAG]` — `library/` prefix is implied for unscoped
  Docker Hub names. Default tag is `latest`.
- `docker://REGISTRY/REPO[:TAG]` — non-Docker-Hub registries
  (`quay.io/...`, `ghcr.io/...`, host:port).
- `docker://REPO@sha256:DIGEST` — pin to a content digest for
  reproducibility. The digest may name either a single-arch image
  manifest (in which case arch selection is a no-op) or an OCI index /
  manifest list (in which case `oci-pull.py` still resolves it to the
  matching `linux/<arch>` entry, just like a tag).

## Pipeline

```
       --image=docker://...
              │
              ▼
   ┌─────────────────────────┐
   │ scripts/oci-pull.py     │  registry pull (urllib + bearer-token)
   │  └ manifest list resolve│
   │  └ layer fetch          │  → cache: $XDG_CACHE_HOME/kbox/oci-layers
   │  └ apply (whiteouts,    │
   │     hardlinks, symlinks)│
   └────────────┬────────────┘
                │ staging/  (+ optional manifest)
                ▼
   ┌─────────────────────────┐
   │ mke2fs -d staging       │  rootless ext4 build
   └────────────┬────────────┘
                │ rootfs.ext4
                ▼   (with --rewrite-uid only)
   ┌─────────────────────────┐
   │ tools/oci-chown         │  libext2fs inode rewrite
   │  └ ext2fs_namei         │  → uid/gid/mode from OCI tar header
   │  └ ext2fs_write_inode   │
   └─────────────────────────┘
```

## Layer cache

Layer blobs are content-addressed (sha256). The cache lives at
`$XDG_CACHE_HOME/kbox/oci-layers/<sha256>` (default
`~/.cache/kbox/oci-layers/`). Writes are atomic
(`tempfile.mkstemp` + `os.replace`); reads re-hash the file and drop
the entry on mismatch, so a corrupted cache is self-healing on the next
pull. Pass `--no-cache` to bypass entirely; use `oci-pull.py prune` to
clear or trim the cache.

## Rootless ownership rewrite (`--rewrite-uid`)

`mke2fs -d` inherits the invoking user's UID into ext4 inodes. Without
intervention, the guest sees its own files owned by a non-root UID,
which breaks setuid binaries and `apk add` install scripts when the
guest is launched with `kbox --root-id` (forces guest uid=0).

The fix runs in three steps:

1. `oci-pull.py --manifest=PATH` records `(uid, gid, mode)` per file,
   directory, and hardlink during layer apply. Symlinks are excluded
   (`lchown` semantics aren't load-bearing for the kbox guest); device
   nodes are excluded (rootless cannot `mknod`; `/dev` is mounted at
   guest runtime). Records are NUL-separated:
   `<uid>\t<gid>\t<mode_octal>\t<path>\0`.
2. `mke2fs -d` builds the ext4 image with invoking-user ownership.
3. `tools/oci-chown <image> <manifest>` opens the image read-write via
   libext2fs, resolves each path through `ext2fs_namei`, and rewrites
   `i_uid` (16-bit lo + hi), `i_gid` (16-bit lo + hi), and `i_mode`
   permission bits (preserving type bits like `S_IFREG`/`S_IFDIR`).
   `ext2fs_close` flushes.

The helper is build-time-only: `tools/oci-chown/Makefile` links against
`-lext2fs -lcom_err` from `e2fsprogs`. The kbox supervisor build is
unchanged. `mkrootfs.sh --rewrite-uid` builds the helper on demand if
the binary isn't present.

When you don't pass `--root-id`, you don't need `--rewrite-uid`: the
guest runs as the host user, host UID matches inode UID, and ownership
is consistent.

## Hardening

The layer-apply path is the main attack surface (a malicious image
could try to write outside the staging directory). Defenses:

- **Path traversal.** `safe_join` strips leading `./` and `/` from tar
  member names and rejects any `..` component before joining onto the
  staging root.
- **Symlink Zip Slip.** Each member's parent directory is realpath-checked
  against the staging root before any write, unlink, or `chmod`. A
  malicious layer that creates `staging/etc -> /etc` and then writes
  `etc/passwd` is rejected because `realpath(staging/etc) = /etc`
  doesn't sit under `realpath(staging)`. File writes additionally pass
  `O_NOFOLLOW`, and pre-existing symlinks at the destination are
  unlinked before `os.makedirs`/`os.chmod`.
- **Hardlink source confinement.** Hardlink targets resolve through
  `safe_join` (or its parent-relative variant for ustar-format
  tarballs, which also runs through `safe_join` to reject `..` after
  normalization). Absolute linknames are rejected. The resolved source
  is realpath-checked against the staging root, and `os.link` is called
  with `follow_symlinks=False` so a staging-resident symlink cannot
  redirect the link to a host file.
- **DoS caps.** `MAX_MANIFEST_BYTES=4 MB`, `MAX_BLOB_BYTES=8 GB`,
  `MAX_TAR_MEMBERS=500_000`. Layer descriptors with declared size over
  the blob cap are rejected before download; the streaming loop also
  caps actual bytes received.
- **Auth handling.** Bearer tokens are stripped on cross-host redirects
  (compared by `netloc`, not just hostname, so a port-change redirect
  on the same host also drops the token).
- **Digest verification.** Every blob is sha256-verified in flight;
  cache reads re-verify before use. Corrupted entries are removed and
  re-fetched.
- **Manifest validation in `oci-chown`.** Every record's uid/gid is
  range-checked (`0 <= v <= UINT32_MAX`); leading sign or whitespace is
  rejected. Mode bits outside `0o7777` are rejected. A manifest tail
  missing the trailing NUL fails loudly with byte offset and record
  index.

The supervisor itself never reads the OCI image at runtime (`kbox`
treats the resulting `.ext4` as opaque LKL filesystem state), so a
mis-applied layer cannot escalate beyond the staging directory.

## Limitations

- Only `docker://` URIs are accepted. No `oci://` (local OCI layout
  directories), no `containers-storage://`. Adding a local OCI layout
  reader is a small follow-up if needed.
- Mutable tags (e.g. `alpine:3.21`) are resolved on every pull. Pin to
  a digest for reproducibility.
- Cosign / notation signature verification is not implemented; treat
  this as a development tool, not a supply-chain control.
- Synthetic parent directories (created when a tarball omits explicit
  parent dir entries) are recorded as `0:0:0755`. Well-formed OCI
  layers always include explicit parent entries, so this only fires on
  malformed input.
- zstd-compressed layer support depends on Python's `tarfile`
  capability (Python 3.14+ on most distros).

## Acceptance

Verified end-to-end on x86_64 (`node1`) and aarch64 (`arm`) hosts:

| Scenario | Result |
|---|---|
| `alpine:3.21` round-trip | 185 inodes; busybox `User=0` after rewrite |
| `node:alpine` round-trip | ~2880 inodes; `/home/node` `User=1000` (uid round-trip) |
| Integration suite vs OCI rootfs | parity with baseline tarball rootfs |

A CI job
([`.github/workflows/build-kbox.yml`](../.github/workflows/build-kbox.yml))
runs the full pipeline against `nginx:alpine` on every PR, verifying
the helper reports a non-zero rewrite count and that
`/etc/nginx/nginx.conf` ends up `User=0/Group=0` and `/usr/sbin/nginx`
mode is `0755`.

#!/usr/bin/env python3
"""Rewrite HEAD commit to have a vanity SHA-1 prefix.

Inserts minimal invisible whitespace (space/tab) padding at the end of
the commit message body.  Each padding byte encodes 1 bit of search
space (space=0, tab=1).

Optimizations (pure CPython, stdlib only):
  - Two-level SHA-1 caching: outer padding hashed once per 256 inner
    iterations; inner loop hashes only 9 bytes per attempt.
  - Precomputed chunk lookup tables eliminate per-bit Python loops.
  - Raw digest() byte comparison skips hex encoding.
  - Method-binding (mid.copy -> local) and for-in iteration cut
    per-attempt Python overhead by ~2x.

Usage:
    scripts/vanity-hash.py [--prefix HEX] [--dry-run]

Prefix defaults to "0000" (16 bits, ~65K expected attempts).
Override via --prefix or `git config kbox.vanity-prefix`.
"""

import hashlib
import re
import subprocess
import sys
import time

VANITY_PREFIX = "0000"


def git(*args, stdin_data=None):
    r = subprocess.run(
        ["git"] + list(args),
        input=stdin_data,
        capture_output=True,
    )
    return r.returncode, r.stdout, r.stderr


def get_prefix(cli_prefix):
    if cli_prefix is not None:
        return cli_prefix.lower()
    rc, out, _ = git("config", "--get", "kbox.vanity-prefix")
    if rc == 0:
        val = out.decode().strip().lower()
        if val:
            return val
    return VANITY_PREFIX


def _build_chunks(n_bits):
    """Precompute all 2^n_bits byte-strings of length n_bits.

    Each byte encodes 1 bit: space (0x20) for 0, tab (0x09) for 1.
    Built once; eliminates the per-bit Python loop from the hot path.
    """
    table = [None] * (1 << n_bits)
    for i in range(1 << n_bits):
        b = bytearray(n_bits)
        v = i
        for bit in range(n_bits):
            b[bit] = 0x09 if (v & 1) else 0x20
            v >>= 1
        table[i] = bytes(b)
    return table


def main():
    import argparse

    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--prefix", default=None, help="hex prefix (default: 0000)")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    prefix = get_prefix(args.prefix)
    if not prefix:
        return 0

    # Cap at 8 hex chars (32 bits).  Longer prefixes would cause
    # _build_chunks() to allocate 2^OUTER_BITS entries -- anything
    # above ~24 bits risks catastrophic memory use in pure Python.
    if not re.fullmatch(r"[0-9a-f]+", prefix) or len(prefix) > 8:
        print(f"invalid hex prefix: {prefix} (max 8 chars)", file=sys.stderr)
        return 1

    # Already matches?
    rc, out, _ = git("rev-parse", "HEAD")
    if rc != 0:
        return 1
    old_head = out.decode().strip()
    if old_head.startswith(prefix):
        return 0

    # Read raw commit object.
    rc, commit_raw, _ = git("cat-file", "commit", "HEAD")
    if rc != 0:
        print("cannot read HEAD", file=sys.stderr)
        return 1

    # Strip any previous vanity padding (trailing space/tab before final \n).
    if commit_raw.endswith(b"\n"):
        body = commit_raw[:-1]
        end = len(body)
        while end > 0 and body[end - 1 : end] in (b" ", b"\t"):
            end -= 1
        body = body[:end]
    else:
        body = commit_raw

    prefix_bits = len(prefix) * 4
    pad_len = prefix_bits + 4  # 16x headroom over expected attempts

    obj_len = len(body) + pad_len + 1  # +1 for trailing \n
    header = f"commit {obj_len}\0".encode()
    base_blob = header + body

    # --- Precompute lookup tables ---
    INNER_BITS = min(8, pad_len)
    OUTER_BITS = pad_len - INNER_BITS

    inner_chunks = _build_chunks(INNER_BITS)
    inner_nl = [c + b"\n" for c in inner_chunks]

    # Build inline digest check for the specific prefix.
    # For all-zero prefixes: raw byte comparison (no hex encoding).
    all_zeros = all(c == "0" for c in prefix)
    full_zero_bytes = prefix_bits // 8
    has_nibble = (prefix_bits % 8) == 4

    base_ctx = hashlib.sha1(base_blob)

    t0 = time.monotonic()
    found_outer_chunk = None  # the bytes of the matching outer chunk
    found_inner_idx = -1
    attempts = 0

    if OUTER_BITS > 0:
        outer_chunks = _build_chunks(OUTER_BITS)

        # Method-bind base_ctx.copy to avoid attribute lookup per
        # outer iteration.
        base_copy = base_ctx.copy

        if all_zeros:
            fzb = full_zero_bytes  # hoist out of loop
            hn = has_nibble

            for outer in outer_chunks:
                mid_ctx = base_copy()
                mid_ctx.update(outer)
                # Method-bind mid_ctx.copy: saves one attribute
                # lookup per inner iteration (~2x speedup measured).
                mc = mid_ctx.copy

                for suffix in inner_nl:
                    ctx = mc()
                    ctx.update(suffix)
                    d = ctx.digest()
                    # Inline zero-prefix check: faster than a function
                    # call for 1-3 byte checks.
                    ok = True
                    for j in range(fzb):
                        if d[j]:
                            ok = False
                            break
                    if ok and hn and (d[fzb] & 0xF0):
                        ok = False
                    if ok:
                        found_outer_chunk = outer
                        break

                if found_outer_chunk is not None:
                    break
        else:
            for outer in outer_chunks:
                mid_ctx = base_copy()
                mid_ctx.update(outer)
                mc = mid_ctx.copy

                for suffix in inner_nl:
                    ctx = mc()
                    ctx.update(suffix)
                    if ctx.digest().hex().startswith(prefix):
                        found_outer_chunk = outer
                        break

                if found_outer_chunk is not None:
                    break
    else:
        if all_zeros:
            fzb = full_zero_bytes
            hn = has_nibble
            bc = base_ctx.copy
            for suffix in inner_nl:
                ctx = bc()
                ctx.update(suffix)
                d = ctx.digest()
                ok = True
                for j in range(fzb):
                    if d[j]:
                        ok = False
                        break
                if ok and hn and (d[fzb] & 0xF0):
                    ok = False
                if ok:
                    found_outer_chunk = b""
                    break
        else:
            bc = base_ctx.copy
            for suffix in inner_nl:
                ctx = bc()
                ctx.update(suffix)
                if ctx.digest().hex().startswith(prefix):
                    found_outer_chunk = b""
                    break

    elapsed = time.monotonic() - t0

    if found_outer_chunk is None:
        limit = (1 << pad_len)
        print(f"exhausted {limit} attempts for prefix \"{prefix}\"",
              file=sys.stderr)
        return 1

    # Identify which inner chunk matched (need the index for padding
    # reconstruction).
    # We broke out of `for suffix in inner_nl` -- `suffix` holds the
    # matching entry.  Find its index to get the raw inner chunk.
    found_inner_idx = inner_nl.index(suffix)

    # Compute attempt count.
    if OUTER_BITS > 0:
        found_outer_idx = outer_chunks.index(found_outer_chunk)
        attempts = found_outer_idx * len(inner_nl) + found_inner_idx + 1
    else:
        attempts = found_inner_idx + 1

    # Reconstruct padding in the same byte order as the SHA-1
    # computation: outer chunk first, then inner chunk.
    padding = found_outer_chunk + inner_chunks[found_inner_idx]
    commit_content = body + padding + b"\n"

    # Verify the hash before touching any refs.
    new_hash = hashlib.sha1(header + commit_content).hexdigest()
    if not new_hash.startswith(prefix):
        print(f"internal error: {new_hash} does not start with {prefix}",
              file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"would rewrite HEAD to {new_hash[:12]}"
              f" ({attempts} attempts, {elapsed * 1000:.0f} ms)")
        return 0

    rc, out, _ = git(
        "hash-object", "-t", "commit", "-w", "--stdin",
        stdin_data=commit_content,
    )
    if rc != 0:
        print("failed to write commit object", file=sys.stderr)
        return 1
    written = out.decode().strip()

    # Compare-and-swap: only update if HEAD still points to the
    # original commit.
    rc2, _, err = git("update-ref", "HEAD", written, old_head)
    if rc2 != 0:
        print(f"update-ref failed (HEAD moved): {err.decode()}",
              file=sys.stderr)
        return 1

    short = written[: max(len(prefix) + 4, 12)]
    print(f"HEAD -> {short}"
          f" (prefix \"{prefix}\", {attempts} attempts, {elapsed * 1000:.0f} ms)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

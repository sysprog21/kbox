# cancel-wrapper fast path (aarch64)

## What this is

A fast path that intercepts calls to musl's `__syscall_cancel` from
inside libc syscall wrappers and replaces them with a direct dispatch
into kbox's rewrite trampoline. The win is concentrated on aarch64
`open+close`, which is the only remaining non-near-native row in the
rewrite baseline (`47.3us` vs `~1.5us` for the other rewritten
syscalls; see `TODO.md`). The reason it lags is that musl's `open()`
wrapper does not call the kernel directly: it goes through
`__syscall_cancel`, and the rewriter's per-SVC-site patcher only sees
the SVC inside `__syscall_cancel` itself, where the wrapper-class
contract does not hold.

The patch redirects the *call site* (the `bl __syscall_cancel`
instruction inside the wrapper function) instead of the SVC, so the
fast-path executes with the wrapper's calling convention -- not the
generic SVC trampoline's.

## What `__syscall_cancel` actually does (musl)

Static-musl's `__syscall_cancel(a, b, c, d, e, f, nr)` (see
`musl/src/thread/__syscall_cancel.c`):

1. Loads `self->cancel` (the calling thread's pthread_cancel state).
2. If a cancellation has been requested AND the thread is in
   `PTHREAD_CANCEL_ENABLE` AND the cancel type is asynchronous, it
   raises the cancel and never returns from the call.
3. Otherwise it issues the syscall (the SVC that the SVC-site
   rewriter currently patches) and returns the raw kernel result
   (`-4095..-1` encodes errno; everything else is the return value).
4. After the SVC, it re-checks the cancel state for deferred
   cancellation and may run the cancel handlers if a cancel arrived
   during the syscall.

The wrapper's calling convention on aarch64:

| Reg     | Meaning                            |
|---------|------------------------------------|
| `x0..x5`| syscall args `a..f`                |
| `x6`    | syscall number `nr`                |
| `x0`    | return value (raw kernel result)   |
| `x7..x18` | caller-clobbered scratch         |
| `x19+`  | callee-saved (preserved)           |

The key facts for kbox:

- errno is *not* set inside `__syscall_cancel`; the libc wrapper
  (e.g. `open()`) inspects the return and sets errno.
- The result register (`x0`) and the dispatch register (`x6`) are
  exactly what `kbox_syscall_rewrite_aarch64_dispatch` already
  consumes via the existing cancel trampoline
  (`kbox_syscall_rewrite_aarch64_cancel_entry` in `src/rewrite.c`).
- All FD bookkeeping happens inside the dispatch path; the cancel
  fast path is just an alternate entry to the same dispatch and
  inherits the existing forwarder semantics unchanged.

## What we lose

Cancellation-point semantics. By bypassing `__syscall_cancel`, the
fast path skips the pre- and post-syscall pthread cancel checks. For
a single-threaded program no cancellation can ever be pending, so
this is a no-op. For a multi-threaded program with a thread that has
been `pthread_cancel`'d, the bypassed `open()` will not act as a
cancellation point and will not raise the cancel until the next real
cancellation point.

This is the only correctness gap. errno propagation, FD bookkeeping,
register preservation, and unwind metadata are all unaffected (we
return to `bl_pc + 4`, exactly where the BL would have returned, with
`x0` set the same way).

## Gating policy

Two conditions must both hold at install time for a cancel-style BL
site to be promoted. The gate is stored in
`kbox_rewrite_runtime::cancel_promote_allowed`, computed once during
`kbox_rewrite_runtime_install()` and consulted from
`rewrite_runtime_should_patch_site()`.

### Condition 1: the binary is static

`launch->interp_elf == NULL && launch->interp_elf_len == 0`. For a
dynamic binary, libc (and therefore the clone wrapper that
`pthread_create` depends on) lives in an interpreter-loaded DSO that
the main-ELF scan cannot see. A dynamic program could also `dlopen`
a DSO that spins up threads at runtime, which is not detectable
statically at all. Promotion for dynamic binaries is unsafe, so the
gate rejects them outright. This also means the cancel-wrapper fast
path only benefits static-musl binaries today; dynamic programs stay
on the existing forwarder path.

### Condition 2: main_elf has no fork-family wrapper sites

`kbox_rewrite_has_wrapper_syscalls(main_elf, ..., {clone, fork,
vfork, clone3})` returns 0. Because the binary is static (condition
1), libc is *part of* `main_elf` — there is no separate interpreter
ELF to scan. Any `pthread_create` → libc clone wrapper compiles
down to a `mov x8, #220; svc 0` site inside `main_elf`'s text
segment, and the wrapper-number scanner catches it. Scanning
`main_elf` alone is therefore sufficient to cover the embedded libc
in a static build; this is the important invariant that makes the
gate sound.

Rationale: no fork-family sites in the main (= only) ELF implies
the program cannot create additional threads, which implies pthread
cancellation cannot be pending on any thread, which makes the
cancel bypass a strict no-op.

### Conservative by design

This gate rejects multi-threaded programs that never actually call
`pthread_cancel` — those would also be safe to promote, but proving
it statically is unreliable. The gate costs nothing on the
`bench-test` target (single-threaded) and trivially preserves
correctness for everything else by leaving the existing forwarder
path in place.

### Known residual limitations

- A static program that invokes `clone`/`clone3` via `syscall(3)`
  (register-indirect `mov x8, x_reg; svc 0`) slips past the
  wrapper-number scanner, which only matches the literal-immediate
  pattern `movz x8, #nr; svc 0`. The gate would approve such a
  binary even though it can actually create threads. This pattern
  is very rare in practice — no test binary in the tree exercises
  it, and musl's own `pthread_create` path uses the immediate form
  — but it is a known unsoundness that would need a stronger
  static analysis to close. Not introduced by this series; the
  underlying scanner predates it.

- The shared-libc musl `__syscall_cancel` calling convention
  differs from the static one (nr in `x0` vs `x6`). Even if
  condition 1 were relaxed, the current BL-site detector would
  not recognize dynamic-musl call sites. Out of scope for this
  fast path.

## Site detection

Pattern (aarch64, walk the segment one 4-byte instruction at a time):

```
mov{z} x6, #imm16     ; syscall number into x6
... within 32 bytes ...
bl <target>           ; opcode 0x94XXXXXX
```

The intermediate instructions are arbitrary (typically arg setup and
maybe a `mov x?, x6`). The 32-byte horizon is a safety bound to keep
the heuristic local; in practice the BL is one or two instructions
after the `mov`.

We deliberately do *not* match plain `b` (opcode `0x14XXXXXX`).
A plain `b` would be a tail call, which has different return
semantics: after the rewrite trampoline executes, control falls
through to `b_pc + 4`, but a tail-call site has no meaningful "next
instruction" -- the surrounding function expects never to come back.
Restricting to BL sidesteps this entire class of misanalysis.

We also do not validate that the BL target is the actual
`__syscall_cancel` symbol. Doing so would require a dynsym/symtab
walk and would only work for symbol-bearing static-musl binaries.
The `mov x6, #nr` constraint is already a strong structural filter
(x6 is not used as an arg register by the kernel ABI on aarch64), and
the single-thread gate makes any false positive a no-op anyway.

## Patch and trampoline

The patch is the same B-relative-to-trampoline encoding the rewriter
already uses for SVC sites:

```
[bl <target>]   ->   [b <trampoline_slot>]
```

The trampoline slot (`AARCH64_REWRITE_SLOT_SIZE` = 32 bytes) is
emitted by `write_aarch64_trampoline` with
`wrapper_kind = SYSCALL_CANCEL`, which causes it to point at
`kbox_syscall_rewrite_aarch64_cancel_entry` (versus the regular
`kbox_syscall_rewrite_aarch64_entry` for SVC sites). The cancel
entry differs from the regular entry in exactly one line: it loads
`nr` from saved `x6` (offset `+40`) instead of saved `x8` (offset
`+56`). Everything else -- register save/restore, the call into
`kbox_syscall_rewrite_aarch64_dispatch`, and the resume sequence --
is identical.

After dispatch, the cancel entry executes:

```
add x16, x19, #4    ; x19 holds origin = bl_pc, so x16 = bl_pc + 4
br  x16
```

This resumes the wrapper at the instruction after the BL, with `x0`
holding the kernel result, which is exactly the state the wrapper
expects after a normal return from `__syscall_cancel`.

`x30` (LR) is restored to whatever the BL site's caller had stored
before the call. We do *not* update it to `bl_pc + 4` even though a
real BL would have. This is fine: AAPCS64 treats x30 as
caller-clobbered across a call, and the wrapper's prologue has
already saved the function's own return address; nothing in the
wrapper body reads x30 between the BL and the function epilogue.

If the BL is more than ±128 MiB from the trampoline page, the
existing veneer fallback in `kbox_rewrite_runtime_install` bridges
the gap exactly the same way it does for out-of-range SVC sites.

## Tests

Unit (`tests/unit/test-rewrite.c`):

- Encodes a synthetic `mov x6, #57; bl ...` (close) and a
  `mov x6, #56; bl ...` (openat) inside an aarch64 ELF segment;
  asserts `analyze_segment` emits a planned site at the BL with
  `width=4` and `original` matching the BL bytes.
- Asserts `kbox_rewrite_encode_patch` for the BL site emits a
  4-byte B with `imm26` pointing at the trampoline.
- Asserts that with `kbox_rewrite_has_fork_sites` true on the same
  ELF, `cancel_promote_allowed` would be 0 and the install path
  would skip the cancel-kind sites (validated through
  `rewrite_runtime_should_patch_site`).

Integration: bench-test under `--syscall-mode=rewrite` on lima
(correctness) and on `arm` (perf delta on `open+close`).

## Performance baseline

Before (real Arm64, `bench-test 1000`, BUILD=release, from TODO.md):

| Syscall    | rewrite |
|------------|---------|
| open+close | 47.3us  |

Target: pull `open+close` into the same ~1.5 us tier as the other
rewritten rows. The numbers will be re-captured on the same `arm`
host with the same release build before/after this change and
recorded in the changelog.

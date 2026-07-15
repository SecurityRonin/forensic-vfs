# 0005 — `safe-read` as the panic-free parsing substrate

**Status:** Accepted (as shipped; `safe-read` published v0.1.0)

## Context

Every leaf reader parses attacker-controllable bytes. The default idiom —
`u32::from_le_bytes(data[off..off+4].try_into().unwrap())` — panics on a truncated or lying
input via out-of-range slice indexing. A forensic tool that panics on hostile evidence has
a denial-of-service bug, and the fix was being re-implemented (often subtly wrong) in each
crate. A real instance: ntfs-forensic's `carve.rs` `parse_filename_attr` indexed directly
and panicked on a crafted `$FILE_NAME` attribute.

## Decision

A single zero-dependency, `no_std`, never-panic crate `safe-read` provides
`le/be_u16/u32/u64(data, off) -> uN`, returning `0` when the read would go out of range
(`off.checked_add(width)` bounds every access). Leaf readers route field reads through it
instead of hand-rolling bounds checks.

## Consequences

- Out-of-range field reads yield a benign `0`, never a crash — the parser then rejects the
  structurally-invalid record through its own validation, loudly, rather than dying.
- One audited, fuzzed implementation replaces N per-crate copies (DRY across the whole
  ecosystem, not just one repo).
- `no_std` + zero-dep means any reader, however constrained, can adopt it.
- This is the *static* partner to a fuzz target: `safe-read` removes the panic; the fuzzer
  proves it. Both are required for an untrusted-input parser.
- Scope boundary: `safe-read` handles fixed-width integer fields. Variable-length and
  structural bounds (record counts, run lengths) remain the reader's responsibility to
  range-check before use.

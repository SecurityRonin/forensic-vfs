# 0004 — Contract impls gated behind an optional `vfs` cargo feature

**Status:** Accepted (as shipped)

## Context

Every reader crate (ewf, ntfs, apfs, …) is independently useful without forensic-vfs — a
caller may want just NTFS parsing with no VFS composition. Making forensic-vfs a hard
dependency of every reader would force the whole contract graph (and its transitive deps)
onto callers who never compose, and would create a dependency cycle risk as forensicnomicon
and the readers co-evolve.

## Decision

Each leaf crate declares `vfs = ["dep:forensic-vfs"]` in `[features]` and puts its contract
impl in a `#[cfg(feature = "vfs")]` module (conventionally `src/vfs.rs`). forensic-vfs is an
*optional* dependency, pulled only when the feature is on.

## Consequences

- A downstream that only parses one format pays nothing for the contract layer.
- VFS composition is one feature flag away, not a fork.
- The pattern is uniform across all 16 production impls, so "does crate X speak the
  contract?" is answered by one grep for `feature = "vfs"` — which is exactly how the
  verified coverage matrix (PRD §6) was built.
- Trap surfaced by this audit: a crate can carry a contract impl **only under
  `dev-dependencies`** (test-only), which looks like coverage but ships none —
  aff4-forensic is in this state and is explicitly listed as not-yet-production.

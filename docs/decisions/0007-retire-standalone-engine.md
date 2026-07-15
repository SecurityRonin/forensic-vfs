# 0007 — Retire the standalone `forensic-vfs-engine` in favor of `crates/engine`

**Status:** Proposed (retirement pending; do-not-publish in force)

## Context

Two VFS engines exist in the fleet: the workspace member `forensic-vfs/crates/engine`
(the WIP resolver that consumes the contracts on the `feat/engine` branch) and a separate
top-level `forensic-vfs-engine` crate. The standalone one predates the contract split and
duplicates the engine's role; some format logic (e.g. tar/7z as `ForensicFs`) currently
lives only there, on an older trait, not on the `FileSystem` contract.

## Decision

`crates/engine` is the canonical engine. `forensic-vfs-engine` is **not to be published**
and is slated for retirement once its still-unique logic is ported onto the contracts.

## Consequences

- One engine, one place to evolve the resolver — no divergence between two engines that
  drift apart.
- Blocking step before retirement: port the format logic that exists *only* in the
  standalone crate (tar/7z on `ForensicFs`) onto the `FileSystem` contract, so nothing is
  lost when it is removed.
- Constraint honored during this work: the WIP `crates/engine` on `feat/engine` is the
  repo owner's branch and is **not modified unilaterally** — this ADR records the
  direction, not a merge.
- Until retirement, the do-not-publish guard stays on `forensic-vfs-engine` so the
  duplicate never reaches a registry.

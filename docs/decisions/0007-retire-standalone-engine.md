# 0007 — VFS crate topology: contract leaf (with resolver) + separate published engine

**Status:** Accepted (2026-07-18). *Reverses the standalone-retirement plan an earlier draft of this ADR proposed — see History. Filename kept for reference stability; the ADR number is the identifier.*

## Context

The universal forensic VFS is split across crates. This ADR settles where each piece
lives: the trait contracts, the generic resolver, and the concrete reader wiring. Two
shapes were considered:

- **Pure contract + one in-workspace engine** (an earlier draft of this ADR): `forensic-vfs`
  = traits only; a `crates/engine` workspace member holds resolver + reader wiring; the
  standalone `forensic-vfs-engine` retired and unpublished.
- **Contract-with-resolver + a separate published engine** (what shipped, and is ratified here).

## Decision

Three roles across **two published crates**:

1. **`forensic-vfs` — the contract leaf** (published, MSRV 1.85). The four trait contracts
   (`ImageSource`, `VolumeSystem`, `CryptoLayer`, `FileSystem`), `Registry`, `PathSpec`,
   `FsMeta`, `FsKind`, bounded-read helpers — **and the generic resolver** (`Registry::resolve`,
   `walk`, `snapshot_view`). The resolver is reader-independent (touches only the four traits,
   names no concrete format, adds no dependency), so it lives in the leaf as the **minimal
   canonical reference resolver**: any tool or test drives it with a fake `Registry` at zero
   dependency cost.

2. **`forensic-vfs-engine` — the orchestrator** (a SEPARATE published repo, MSRV 1.88).
   `default_registry()` wiring the ~17 concrete reader probes + `Vfs::open(path)` host
   bootstrap; depends *down* on the leaf + every reader. It is its own repo — NOT a workspace
   member of the contract — so the contract's CI builds without 17 reader trees, the 1.85/1.88
   MSRV split is expressible, and its supply-chain gates (deny/vet/fuzz over 16 reader trees)
   never pollute the leaf's audit surface.

3. `crates/engine` (the in-workspace engine the earlier draft favored) is **retired**: with the
   resolver in the leaf, the engine's remaining job is pure wiring, which belongs in the
   orchestrator repo.

### The leaf invariant

The leaf's purity axis is **"zero reader dependencies, zero format knowledge, no dependency or
MSRV raise"** — NOT "zero logic." `forensic-vfs` is an *interface* crate (unlike the sibling
*knowledge* crate `forensicnomicon`, which is pure facts): a reader-independent algorithm
generic over the four traits is the contract's operational semantics and belongs here — the same
category as a trait default method.

### Resolver evolution (the one contested point — 2026-07-18 design panel: Fable / Gemini / Codex)

Resolver *behavior* is forensic decision policy and it evolves (probe ordering, ambiguity, first-
match vs multi-result, the coming archive-detour selection — ADR 0008). **Dependency-stability is
not behavioral-stability**: a zero-dep crate can still churn its behavior, and 17 readers pin this
leaf. Therefore:

- The leaf holds a **minimal, frozen reference resolver.** Advanced resolution policy (archive
  `AccessPlan` multi-result, segment-set selection, ambiguity reporting, `ResolverOptions`) does
  **NOT** grow inside the leaf — it lives in the archive-core adapter and/or the engine.
- **Extract a `forensic-vfs-resolver` middle crate** at the first of: (a) a second consumer needs
  the advanced policy, or (b) the archive work forces selection logic that can't stay cleanly in
  the adapter. Until a trigger fires, no new crate.

## Consequences

- **Governance now matches shipped reality.** This ADR previously read "Proposed / do-not-publish";
  the standalone engine has since been published (0.1.0) and is canonical. Any lingering
  do-not-publish guard on `forensic-vfs-engine`'s Cargo.toml is obsolete and should be removed.
- **Two repairs the panel surfaced (tracked follow-ups):**
  1. **Delete the engine's private `fn resolve`** (`forensic-vfs-engine/src/lib.rs:98`) — verified a
     line-for-line duplicate of `Registry::resolve` (two resolvers = exactly the drift the earlier
     draft feared, relocated). Delegate to `Registry::resolve`; keep the *separate* `open_base()`
     host bootstrap; add a golden-fixture test asserting `Vfs::open` produces the same resolved
     stack as a direct `Registry::resolve`.
  2. **`Registry::resolve` descends filesystems/volumes/containers but NOT `CryptoProbe`** — so the
     headline `E01 → GPT → BitLocker → NTFS` does not auto-resolve the crypto layer. Add a
     crypto-descent path (with `CredentialSource` injection).
- **Behavioral-semver discipline for the resolver:** deterministic probe ordering, ambiguity
  reporting (not silent first-wins), golden-stack fixtures across container/volume/crypto/
  filesystem/archive, and an engine↔leaf compatibility test — because a heuristic change can alter
  forensic output without changing public types (`#[non_exhaustive]` alone does not cover that).

## History

An earlier draft of this ADR (status *Proposed*, never accepted) proposed the reverse: retire the
standalone `forensic-vfs-engine`, make an in-workspace `crates/engine` canonical, and keep the
standalone unpublished. That plan was overtaken *before* ratification — the generic resolver moved
into the contract leaf and the standalone engine was rewritten onto the contracts and published, at
which point `crates/engine` became redundant and was removed. The verbatim original draft is in this
file's git history (`git log --follow -- docs/decisions/0007-retire-standalone-engine.md`).

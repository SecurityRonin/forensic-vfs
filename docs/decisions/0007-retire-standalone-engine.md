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

Three roles across **three published crates**:

1. **`forensic-vfs` — the contract leaf** (published 0.4, MSRV 1.85). The byte edge
   (`ImageSource`) and the five layer-open traits (`ContainerOpen`, `ArchiveOpen`,
   `VolumeSystemOpen`, `EncryptionOpen`, `FileSystemOpen`), the `Openers` dispatch table,
   `PathSpec`, `FsMeta`, `FsKind`, and bounded-read helpers. It names no concrete format and
   adds no reader dependency.

2. **`forensic-vfs-resolver` — the `SourceOpen` orchestrator** (published 0.1, this
   workspace). `impl SourceOpen for Openers` plus `walk` and `snapshot_view`: the
   reader-independent recursive descent that probes the five layer-opens at each node and
   re-enters until a filesystem mounts (`openers.open(source) -> Resolved`). It touches only the
   leaf's traits — names no concrete format, adds no reader dependency — so any tool or test
   drives it with a fake `Openers` at zero dependency cost. It was extracted from the leaf once
   the archive layer (ADR 0008) forced richer selection policy — the trigger this ADR named
   (see *Resolver evolution*).

3. **`forensic-vfs-engine` — the wiring** (a SEPARATE published repo, MSRV 1.88).
   `default_openers()` wiring the ~17 concrete readers + `Vfs::open(path)` host bootstrap;
   depends *down* on the leaf, the resolver, and every reader. It is its own repo — NOT a
   workspace member of the contract — so the contract's CI builds without 17 reader trees, the
   1.85/1.88 MSRV split is expressible, and its supply-chain gates (deny/vet/fuzz over 16 reader
   trees) never pollute the leaf's audit surface.

4. `crates/engine` (the in-workspace engine the earlier draft favored) is **retired**: the
   descent lives in the resolver and the concrete wiring in the engine repo, so no in-workspace
   engine member remains.

### The leaf invariant

The leaf's purity axis is **"zero reader dependencies, zero format knowledge, no dependency or
MSRV raise."** `forensic-vfs` is an *interface* crate (unlike the sibling *knowledge* crate
`forensicnomicon`, which is pure facts): it carries the byte edge, the five layer-open traits,
and the `Openers` table. The reader-independent descent (`SourceOpen`) is the contract's
operational semantics, but it evolves as forensic policy — so it lives one hop out in
`forensic-vfs-resolver` (still zero reader dependencies) rather than in the leaf, keeping the 17
readers that pin the leaf insulated from resolver churn (see *Resolver evolution*).

### Resolver evolution (the one contested point — 2026-07-18 design panel: Fable / Gemini / Codex)

Resolver *behavior* is forensic decision policy and it evolves (probe ordering, ambiguity, first-
match vs multi-result, the archive-layer selection — ADR 0008). **Dependency-stability is not
behavioral-stability**: a zero-dep crate can still churn its behavior, and 17 readers pin this
leaf. The panel therefore named a trigger for splitting the descent out of the leaf — and it has
since fired:

- The descent lives in **`forensic-vfs-resolver`**, a dedicated crate depending on the leaf's
  traits alone. Advanced resolution policy (archive `AccessPlan` multi-result, segment-set
  selection, ambiguity reporting, `ResolverOptions`) grows there and in the archive-core adapter
  — never inside the leaf.
- The extraction trigger the panel named — "the archive work forces selection logic that can't
  stay cleanly in the adapter" — fired with ADR 0008, so the middle crate was created rather than
  deferred. The leaf now carries contracts only; its version is no longer bumped by resolver
  churn.

## Consequences

- **Governance now matches shipped reality.** This ADR previously read "Proposed / do-not-publish";
  the standalone engine has since been published (0.1.0) and is canonical. Any lingering
  do-not-publish guard on `forensic-vfs-engine`'s Cargo.toml is obsolete and should be removed.
- **Two repairs the panel surfaced (tracked follow-ups):**
  1. **Delete the engine's private `fn resolve`** (`forensic-vfs-engine/src/lib.rs:98`) — verified a
     line-for-line duplicate of `SourceOpen::open` (two resolvers = exactly the drift the earlier
     draft feared, relocated). Delegate to `SourceOpen::open`; keep the *separate* `open_base()`
     host bootstrap; add a golden-fixture test asserting `Vfs::open` produces the same resolved
     stack as a direct `SourceOpen::open`.
  2. **`SourceOpen::open` descends filesystems/volumes/containers but NOT `EncryptionOpen`** — so the
     headline `E01 → GPT → BitLocker → NTFS` does not auto-resolve the encryption layer. Add a
     encryption-descent path (with `CredentialSource` injection).
- **Behavioral-semver discipline for the resolver:** deterministic probe ordering, ambiguity
  reporting (not silent first-wins), golden-stack fixtures across container/volume/encryption/
  filesystem/archive, and an engine↔leaf compatibility test — because a heuristic change can alter
  forensic output without changing public types (`#[non_exhaustive]` alone does not cover that).

## History

An earlier draft of this ADR (status *Proposed*, never accepted) proposed the reverse: retire the
standalone `forensic-vfs-engine`, make an in-workspace `crates/engine` canonical, and keep the
standalone unpublished. That plan was overtaken *before* ratification — the generic resolver moved
into the contract leaf and the standalone engine was rewritten onto the contracts and published, at
which point `crates/engine` became redundant and was removed. The verbatim original draft is in this
file's git history (`git log --follow -- docs/decisions/0007-retire-standalone-engine.md`).

# 0009 — `FileId` relocates to `forensicnomicon-core`

**Status:** Accepted (2026-07-18); implementation lands with its first cross-crate consumer.

## Context

`FileId` (ADR [0002](0002-opaque-fileid-filesystem.md)) is the opaque filesystem-object
identity every `FileSystem` names its nodes with — `NtfsRef{entry,seq}`,
`ExtInode{ino,gen}`, `ApfsOid{oid,xid}`, `FatDirEntry`, `IsoExtent`, `Opaque`. It currently
lives in `forensic-vfs` (`crates/core/src/fs.rs`).

A second crate now needs it. The `[P]` evidential address (in `state-history-forensic`)
keys a persistent artifact on its `FileId` — stabler than a path (it survives renames, and
the second field on each variant, `seq`/`gen`/`xid`, is a slot-reuse discriminator that
distinguishes a reallocated inode/MFT record from the original). If `state-history-forensic`
reached for `forensic-vfs::FileId`, a KNOWLEDGE-layer identity crate would depend **up** on
the byte-VFS contract — the wrong direction — and a dedicated `forensic-types` crate would
fragment the vocabulary into a third home.

## Decision

Relocate `FileId` into **`forensicnomicon-core`** (the zero-dep KNOWLEDGE leaf), beside
`FsKind`. `forensic-vfs` keeps `pub use forensicnomicon_core::FileId`, so every existing
`forensic_vfs::FileId` consumer is unaffected.

This is the **`FsKind` keystone precedent** (fn-core 1.2, ADR
[0006](0006-knowledge-in-forensicnomicon.md)): `FileId` is pure, format-defined identity
*structure* — how each filesystem names an object — which is KNOWLEDGE, not VFS machinery.
It is a zero-dep enum that already derives `Eq + Hash`, so it is a component of an
identity key by construction.

## Consequences

- **Correct dependency direction.** Everyone deps **down** onto the knowledge leaf:
  `forensic-vfs` already depends on and re-exports from `forensicnomicon-core`;
  `state-history-forensic` depends on `forensicnomicon-core` (a first-party knowledge leaf,
  so its "pure types, no external deps" charter holds) rather than on `forensic-vfs`. No
  cycle (`forensicnomicon-core` depends on nobody), and no new crate.
- **Zero consumer breakage** — the `forensic-vfs::FileId` re-export is API-identical, so
  the move is invisible to every current caller.
- **Cost** — one `forensicnomicon-core` minor bump plus a fleet reconvergence, the same
  well-worn process as the FsKind move. Because it is additive (a new type in fn-core, a
  re-export in the leaf), no consumer break rides it.
- **Supersedes** the earlier design placement — a `state-history-forensic → forensic-vfs`
  dependency — which is removed from `issen/docs/plans/universal-address-design.md`
  (residuals 1 and 4 there are closed by this ADR).

Implementation is tied to the first cross-crate consumer — the `[P]` evidential address —
or a proactive `forensicnomicon-core` relocation, whichever lands first.

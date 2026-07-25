# 0014 — Archive & logical containers surface as browsable `FileSystem`s; the mount-folder convention stays in the consumer

**Status:** Proposed — design accepted; implemented in `forensic-vfs-engine` (the follow-up) after which `4n6mount` drops its local adapter. Interim unblock: `4n6mount` PR #7 (`SyntheticFs`).

## Context

`Vfs::open_all` descends an image looking for **disks with filesystems**. For a
container that carries a *file tree* rather than a disk image, it yields nothing
useful:

- **Archive containers** (zip / 7z / tar / tar.gz / tar.bz2): the resolver treats
  each member as a *nested-evidence candidate* (hunting for a disk image inside a
  zip), so a file-bearing archive resolves to `fs: None`. Worse, a plain zip is
  claimed by the Zip-framed AFF4 decoder and *errors* ("information.turtle not
  found").
- **Logical containers** (FTK AD1 / AFF4-Logical / DAR): file trees with no disk
  underneath — not surfaced as a filesystem at all.

So a consumer that wants to *browse* such a container (e.g. `4n6mount`'s FUSE/Dokan
mount) must build its own adapter from the raw flat entry lists
(`archive_core`'s `ArchiveContents`, `disk_forensic::logical`'s `LogicalEntry`).
That duplicates the container→tree logic in every consumer and violates the fleet
VFS-abstraction policy — *a consumer must not special-case formats*. Lived case:
`4n6mount` added a local `SyntheticFs` **plus** a `disk-forensic` dependency purely
to unblock its `mount-smoke` (the archive/logical rows failed "no filesystem
detected").

## Decision

1. **`forensic-vfs-engine` surfaces archive and logical containers as a browsable
   `forensic_vfs::FileSystem`** — an `ArchiveFs` (over `archive-core`) and a
   `LogicalFs` (over `disk_forensic::logical`) — so `Vfs::open_all` returns
   `fs: Some(...)` for zip/7z/tar/tar.gz/tar.bz2 and AD1/AFF4-Logical/DAR.
2. **The surfaced filesystem exposes files at their NATURAL paths** — the
   container's own member paths — and nothing else. No consumer's mount layout is
   baked in.
3. **The mount-folder convention stays in the CONSUMER.** Volume nesting, the
   read-only overlay, `root` / `_partition<N>` naming (e.g. `4n6mount`'s ADR-0010)
   are applied *on top* of the natural-path filesystem — exactly as they already
   are for real disk filesystems (`ntfs-forensic` returns files; the consumer wraps
   them in `<volume>/`). The shared VFS stays format- and UX-agnostic.
4. **Detection order must not steal physical disks.** Surfacing archive/logical is
   a *fallback* for containers that carry a file tree, tried only when the disk
   decoders decline — a **physical** AFF4 (a disk image in a Zip-framed AFF4) still
   routes to the AFF4 disk decoder, never to `ArchiveFs`/`LogicalFs`.

## Consequences

- Every consumer gets browsable archive/logical containers for free; the
  container→tree logic lives once, in the engine.
- **`4n6mount` deletes its local `SyntheticFs` and its `disk-forensic` dependency**
  once this ships — the existing `EngineFs`/`MultiPartitionFs` path handles the
  engine-surfaced filesystem uniformly.
- Ships as a `forensic-vfs-engine` minor; consumers reconverge on the new engine
  version. `forensic-vfs` (this crate) is unchanged unless a `FileSystem`
  convenience is added; the `FileSystem` contract already suffices.
- The interim `4n6mount` `SyntheticFs` (PR #7) is a correct local unblock and is
  explicitly *deletable* once this lands — it is not the final architecture.
- Companion to `4n6mount` ADR-0010 (which owns the mount-folder convention) and the
  fleet VFS-abstraction policy in `ronin-issen` CLAUDE.md.

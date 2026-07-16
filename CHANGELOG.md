# Changelog

All notable changes to `forensic-vfs` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0]

### Changed

- **BREAKING: `FsKind` is now the canonical string-backed newtype re-exported from
  `forensicnomicon-core` 1.2.0**, replacing the local `enum FsKind` (named variants +
  `Other`). One filesystem-family identity type is now shared across the fleet — a reader
  and the VFS agree without a per-crate enum (see [ADR 0006](docs/decisions/0006-knowledge-in-forensicnomicon.md)).
  Consumers use the associated consts (`FsKind::NTFS`, `FsKind::EXT`, …) instead of enum
  variants, and match through `as_str()` / `known()` rather than exhaustively.
- `forensic-vfs`'s `serde` feature now forwards to `forensicnomicon-core/serde`, so a
  serialized `FsKind` round-trips as its bare string identifier.

### Added

- First-class filesystem identities for **btrfs, zfs, ufs, refs, zip, ad1, dar** (carried
  by the newtype's `known()` set), reachable through the `fs:<kind>` URI locator.
- **The generic layer resolver now lives in the core leaf as `Registry::resolve`.** Given a
  `DynSource` and a starting `PathSpec`, it sniffs a head+tail window, matches the registered
  filesystem/volume-system/container probers, and descends container→volume→filesystem to a
  mounted `dyn FileSystem` (depth-capped, panic-free). The supporting generic surface moves
  with it: `Resolved`, `Evidence`, `SnapshotView` + `snapshot_view` / `epoch_from_create_time`
  (the `[H]` snapshot *view*), and `walk` / `WalkEntry` for whole-filesystem enumeration. Any
  tool or test can now drive detection registry-first, without a reader-wired orchestration
  crate. Adds a non-optional `state-history-forensic` dependency for `SnapshotView`'s `EpochTag`.

### Removed

- **The `forensic-vfs-engine` workspace member is gone.** It carried the resolver plus the
  reader-dependent wiring (concrete `*Probe` impls, `default_registry()`, the by-path
  `Vfs`/snapshot API, EWF-by-path base resolution). Its generic resolver moved into core
  (above); the reader-wired remainder is relocating to the fleet orchestration layer, so the
  workspace is now core-only.

### Removed

- **BREAKING: the `FsKind::Other` variant.** An unrecognized `fs:` token in a `PathSpec`
  URI is now a hard decode error rather than collapsing to `Other` — an unknown filesystem
  is surfaced, not silently absorbed.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0](https://github.com/SecurityRonin/forensic-vfs/compare/forensic-vfs-v0.9.0...forensic-vfs-v0.10.0) - 2026-09-20

### Added

- *(core)* StreamKind gains HfsDataFork and Data

## [0.9.0](https://github.com/SecurityRonin/forensic-vfs/compare/forensic-vfs-v0.8.0...forensic-vfs-v0.9.0) - 2026-08-24

### Added

- *(fs)* distinguish char/block devices and FIFOs from sockets ([#23](https://github.com/SecurityRonin/forensic-vfs/pull/23))

## [0.8.0](https://github.com/SecurityRonin/forensic-vfs/compare/forensic-vfs-v0.7.2...forensic-vfs-v0.8.0) - 2026-08-23

### Added

- *(encryption)* a scheme a TreeOpen can honestly ask for credentials with ([#22](https://github.com/SecurityRonin/forensic-vfs/pull/22))
- *(tree)* a directory-rooted opener seam for captured file trees ([#20](https://github.com/SecurityRonin/forensic-vfs/pull/20))

## [0.7.2] - 2026-08-09

### Fixed

- Widen the `state-history-forensic` requirement from `"0.1"` to `"0.2"`. For a
  0.x crate cargo treats the minor as the major, so `"0.1"` could not reach
  0.2.x and no lock refresh would ever cross it. Because every `*-core`
  filesystem crate depends on `forensic-vfs`, this requirement is what pinned
  the whole graph to the 0.1 line — a consumer widening its own direct
  requirement first resolves both versions side by side instead of converging.
  0.2.0 was additive (it added the `[P]` persistent evidential address), and
  the MSRV is unchanged: 0.2.1 requires 1.75, as does this crate.

## [0.7.1] - 2026-08-05

Backfilled. 0.7.1 published without a changelog entry, and it carried an MSRV
change that consumers need to see.

### Fixed

- Declare the MSRV this crate actually has: **1.85 → 1.75**. The higher floor
  was over-declared and propagated to every downstream consumer.
- Regenerate `Cargo.lock` at v3, which the 1.75 floor requires — a v4 lockfile
  fails to parse on older toolchains and reads as a language-level MSRV failure
  when it is not one.
- Supply-chain: trust our own crates rather than exempting them, and record vet
  entries for the versions the v3 lockfile resolves.

## [0.7.0] - 2026-07-20

### Added

- `FileSystem::volume_label()` — the defaulted filesystem-label accessor (readers
  implement per-fs: NTFS `$VOLUME_NAME`, FAT/exFAT label, ext4 `s_volume_name`,
  APFS volume name; the leaf's contribution is the `None` default). Additive — every
  existing reader impl keeps compiling on the default.

## [0.6.1] - 2026-07-20

### Documentation

- Refresh the crates.io README + docs to the new `Locator` / `loc:` / `file:` names.
  0.6.0 published its README snapshot from the rename commit, before the docs sweep, so
  the crates.io landing page lagged the source; this patch re-snapshots it.

## [0.6.0] - 2026-07-20

### Changed (breaking)

- Renamed the locator vocabulary (ADR 0012/0013): type `PathSpec` -> `Locator` (module
  `pathspec` -> `locator`; `PathSpec::os()` -> `Locator::file()`), base layer token `os:`
  -> `file:`, and URI scheme `fvfs:` -> `loc:`. `to_uri` now emits `loc:`/`file:`.
- `pub type PathSpec = Locator` remains a `#[deprecated]` alias, and `from_uri` still
  decodes legacy `fvfs:`/`os:` URIs, so no persisted locator is stranded.

## [0.5.0](https://github.com/SecurityRonin/forensic-vfs/compare/forensic-vfs-v0.4.3...forensic-vfs-v0.5.0) - 2026-07-19

### Added

- *(core)* re-export FileId from forensicnomicon-core, pin fn-core 1.4 (ADR 0009)

## [0.4.3](https://github.com/SecurityRonin/forensic-vfs/compare/forensic-vfs-v0.4.2...forensic-vfs-v0.4.3) - 2026-07-19

### Added

- *(fs)* GREEN — add deleted_nodes() rich deleted-enumeration surface
# Changelog

All notable changes to `forensic-vfs` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- release-plz appends new versions above this line, newest first. -->

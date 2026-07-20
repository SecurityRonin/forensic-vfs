# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

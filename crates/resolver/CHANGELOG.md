# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2] - 2026-08-09

### Fixed

- Widen the `state-history-forensic` requirement from `"0.1"` to `"0.2"`,
  matching `forensic-vfs` 0.7.2. Both members of this workspace inherit the
  requirement, so both had to be released for a consumer's graph to converge —
  publishing `forensic-vfs` alone left `forensic-vfs-resolver 0.3.1` still
  requiring `^0.1`, and any consumer of both resolved 0.1.1 and 0.2.1 side by
  side. Measured in `forensic-vfs-engine`, where `cargo tree -i` named this
  crate as the remaining holder of the 0.1 line.

  No API change: the resolver's own surface is untouched, and 0.2.0 of the
  dependency was additive.

## [0.3.1] - 2026-07-20

### Changed

- Widen the `forensic-vfs` requirement to `0.7` (carries `FileSystem::volume_label()`).

## [0.2.0](https://github.com/SecurityRonin/forensic-vfs/compare/forensic-vfs-resolver-v0.1.4...forensic-vfs-resolver-v0.2.0) - 2026-07-19

### Added

- *(resolver)* resolve_to_source() raw-source terminal (ADR 0011)
# Changelog

All notable changes to `forensic-vfs-resolver` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- release-plz appends new versions above this line, newest first. -->

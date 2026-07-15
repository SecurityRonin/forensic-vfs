# 0006 — Knowledge in forensicnomicon; implementation in dedicated crates

**Status:** Accepted (organizing principle)

## Context

Forensic "knowledge" (what a boot signature means, MITRE/LOLBin mappings, temporal-format
hints, partition-scheme tables) was drifting into individual reader crates and being
duplicated. Separately, cross-cutting *implementation* concerns (temporal math, byte
reading) were each re-derived per crate. Two different kinds of duplication with two
different right answers.

## Decision

Split by kind:

- **Knowledge → `forensicnomicon`.** One hub owns the facts: `report::Finding` (the shared
  finding type every `VolumeSystem`/`CryptoLayer` returns), `temporal` hints,
  `boot_signatures`, `partition_schemes`, MITRE/LOLBin tables. Contracts depend *up* into
  it (`findings() -> forensicnomicon::report::Finding`).
- **Implementation → dedicated crates.** Temporal computation lives in `timeglyph`
  (`PosixNs` nanosecond spine, FILETIME/civil converters). Byte reading lives in
  `safe-read` ([0005](0005-safe-read-substrate.md)).

## Consequences

- A fact is stated once, in forensicnomicon, and referenced — not copied into each reader.
- A computation is implemented once, in its crate, and depended on.
- The distinction matters: temporal *knowledge* (which format a timestamp is, its epoch)
  belongs in forensicnomicon; temporal *math* (converting it) belongs in timeglyph. Forcing
  one crate to do both re-creates the coupling this split removes.
- Deliberate non-goal: **do not force** consolidation where the apparent duplication is
  per-format *semantics* rather than an exact copy. This audit found temporal reader logic
  is format-specific (not copy-paste) and left it in place, adding `timeglyph::secs`
  convenience for the common seconds-caller instead of a forced merge.

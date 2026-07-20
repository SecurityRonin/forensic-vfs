# 0013 — Rename `PathSpec` → `Locator`; wire scheme `fvfs:` → `loc:`

**Status:** Accepted — implemented in `forensic-vfs` 0.6.0 / `forensic-vfs-resolver` 0.3.0 (2026-07-20)
**Bundles with:** ADR [0012](0012-file-layer-and-segment-set-naming.md) — both are wire-format/API-breaking naming changes and ship in the **same** `forensic-vfs 0.6` breaking release, so the fleet reconverges once.

## Context

The type `PathSpec` (`crates/core/src/pathspec.rs`) is the recursive **access-route
locator** — the chain of layers describing *how* an examiner reached a set of bytes
(`file:img.E01|volume:gpt,1|fs:ntfs,...`). Its canonical URI carries the scheme prefix
`fvfs:` (`const SCHEME = "fvfs:"`, `uri.rs`), an abbreviation of the crate name
*forensic-vfs*, chosen to parallel dfVFS's `dfvfs:`.

The name has become actively confusing since the evidential-address design
(`issen/docs/plans/universal-address-design.md`) split addressing into two worlds:

- **`PathSpec` is the examiner-world *access route / custody record*** — "how I reached
  the bytes," explicitly *not* identity. The design doc calls it "the recursive
  locator" / "the access locator" and frames it as "custody — a record of an action."
- **`PersistentAddress` (and the deferred Universal Evidence Address) is the
  subject-world *identity*** — "what this object is."

Three concrete collisions the name `PathSpec` now causes:
1. It is **not a filesystem path** — it is a layer-descent chain. "PathSpec" reads as
   "a path-string specification," the one thing it is not.
2. `PersistentAddress` literally has a **`path: Vec<u8>` field** (the real fs path).
   So "PathSpec" and "the path *in* the Address" are two different things sharing the
   word.
3. `fvfs:` ties the *wire format* to the *library name*: opaque to a reader who does
   not know the crate, and stale if the crate is ever renamed.

## Decision

1. **Rename the type `PathSpec` → `Locator`** (module `pathspec.rs` → `locator.rs`).
   The name the design doc already uses ("the recursive locator"). It names the
   concept — an access route / resolution chain — and cannot be mistaken for a
   filesystem path or for identity. (`AccessRoute` was considered and is a fine
   synonym; `Locator` wins on being the term already in the prose and the shorter of
   the two.)
2. **Rename the wire scheme `fvfs:` → `loc:`.** Concept-named, not library-named;
   matches the type. (The alternative — keep `fvfs:` because a scheme names the
   dialect/producer, not the type — was weighed and rejected here in favor of one
   consistent `loc`-rooted vocabulary across the type and its serialization.)
3. **Combined with ADR-0012**, `Locator::os()` also becomes `Locator::file()` and the
   base layer token `os:` becomes `file:` — the whole locator vocabulary lands honest
   in one release.

### Migration / deprecation surface (one release)

- `pub type PathSpec = Locator;` carrying `#[deprecated(note = "renamed to Locator")]`
  — every current `forensic_vfs::PathSpec` consumer keeps compiling for one release.
- Decode (`from_uri`) **accepts both `loc:` and `fvfs:`** (and both `file:` and `os:`
  per 0012); encode (`to_uri`) **emits only `loc:`/`file:`**. So a persisted `fvfs:`
  URI (saved session, exported case-file provenance) still parses, and re-serializes
  in the new form — no data is stranded, and the round-trip invariant holds for the
  new form.
- The deprecated alias and the legacy-scheme decode arm are removed in the following
  minor release (call it out in the CHANGELOG both times).

## Consequences

- **Breaking `forensic-vfs` release (0.5 → 0.6).** Blast radius (real repos, excluding
  the throwaway `*-adr11` worktrees): `forensic-vfs-engine` (18 refs), `4n6mount`
  (9), `issen` (11); `disk-forensic` clean (0). The 16 filesystem/container readers do
  **not** reference `PathSpec` (they implement `FileSystem`/`FileId`), so this is a
  *much* smaller reconverge than the 0.4→0.5 migration — engine + 4n6mount + issen
  only. The deprecation alias means those consumers can migrate to `Locator` at
  leisure within the 0.6 line rather than in lockstep with the bump.
- **Wire-format change is compat-guarded**, so the "crown-jewel round-trip invariant"
  is preserved for `loc:`/`file:` and legacy `fvfs:`/`os:` still decode — no stored
  locator is orphaned.
- **`dfvfs:` parallel is lost** — a minor cost; `loc:` stands on its own as a
  concept-named scheme and no longer advertises the implementation.
- Scoped strictly to the locator (`Locator`/`uri.rs`); **no change** to
  `PersistentAddress`, `FileId`, `FsKind`, or any identity type (ADR
  [0009](0009-fileid-in-forensicnomicon-core.md), the address design doc).

Implementation lands with the 0.6 cut (bundled with ADR-0012).

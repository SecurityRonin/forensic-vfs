# 0012 — Rename the base layer `os:` → `file:`; name EWF segment sets as a range

**Status:** Part 1 (`os:`→`file:` rename) Accepted — implemented in `forensic-vfs` 0.6.0 (2026-07-20). Part 2 (EWF segment range in the `File` layer) deferred to a later release.

## Context

`Layer::Os { path: PathBuf }` is documented as "the base OS path — the only parentless
layer" (`pathspec.rs`) — the root of every `PathSpec` chain, distinct from a derived
`Layer::Range` root (`Vfs::open_source` seeds one for an in-memory/nested/carved byte
source that was never a top-level piece of evidence). Two problems surfaced discussing
real Case-001 locators:

1. **`os:` is ambiguous about *whose* operating system.** The name reads as "the
   operating system," which a reader can easily take to mean the *subject* machine's
   live OS (e.g. a live-triage tool reading `C:\Windows\...` off a running box) rather
   than what it actually means: *a real file, openable through the current process's
   filesystem APIs* — local disk, USB stick, mounted network share, FUSE mount, all
   identical from that vantage point. "Operating system" is the wrong axis; the layer
   says nothing about which OS, or whether the file is local, removable, or networked.

2. **A multi-segment EWF acquisition is named by its first segment alone, and looks
   like one file.** `forensic-vfs-engine::open_base` calls `ewf::EwfReader::open(path)`,
   which internally calls `discover_segments(path)` and silently pulls in every sibling
   segment (`.E02`, `.E03`, …, or the 2-letter rollover `.EAA`…`.EZZ` past `.E99`). But
   `PathSpec::os(path)` records only that first segment's path string. So a rendered
   locator like `os:20200918_0417_DESKTOP-SDN1RPT.E01|volume:gpt,1|fs:ntfs,...` reads as
   a single file when the evidence is actually backed by four (`.E01`–`.E04`,
   ~6.4 GB combined on this case). That under-describes the exhibit for custody/hashing
   (hashing "the exhibit" needs all segments; the locator names one), for missing-segment
   detection (a corrupt/absent middle segment gives no signal from the locator alone),
   and for a human glancing at the URI.

Neither problem is an identity-layer concern. `PathSpec` is the **access-route locator**
(examiner-world: how the bytes were reached), not the `[P]` `PersistentAddress` identity
key (`state-history-forensic`, design doc
`issen/docs/plans/universal-address-design.md`) — so the ordinals-are-never-identity rule
that bans a partition index from `PersistentAddress::volume` does **not** apply here:
segment sequence in an EWF acquisition is the acquisition's genuine physical structure
(individually hashed per segment, not reorderable the way a partition table is), not an
anti-forensic-manipulable ordinal. This ADR is purely about the locator's honesty and
readability.

## Decision

### 1. Rename `Layer::Os` → `Layer::File`

`os:` becomes `file:` in both the enum variant and the URI token (`layer_encode` /
`layer_decode` in `uri.rs`, the `PathSpec::os` constructor renamed to `PathSpec::file`).
No collision with `Layer::Fs` (`fs:ntfs,...`, a *mounted, parsed* filesystem) — the two
already co-occur without ambiguity today (`file:ntfs.img|fs:ntfs,...`, a bare NTFS image
with no container/volume layer between): one names *where the bytes physically come
from*, the other *what format is parsed on top*. "File" is medium-agnostic by
construction, which is the property `os:` was missing.

### 2. Record the EWF segment range in the `File` layer

When `open_base` resolves a multi-segment EWF acquisition, the `File` layer records the
verified-contiguous segment extension range (`E01`–`E04`, or, for a set crossing the
`.E99`→`.EAA` rollover, the mixed-notation range e.g. `E01`–`EAB`) rather than only the
first segment's bare path. Rendered form: `file:20200918_0417_DESKTOP-SDN1RPT.E01-E04`
(exact field/encoding TBD at implementation; likely an optional `segment_range: Option<(String, String)>` alongside `path`, since a bare single-file source has none).

This reuses the domain's own naming vocabulary (every EWF-literate examiner already
reads `.E01`/`.E02` fluently) rather than inventing a new encoding (a `+3` count was
considered and rejected: a count alone can't assert **contiguity**, only cardinality —
`E01, E02, E04` present with `E03` missing is a materially different, and forensically
significant, fact that a range naturally exposes and a count hides).

**Load-bearing requirement:** the range MUST be built from a verified-contiguous segment
list (the same list `discover_segments`/`EwfReader::open` already assembles and opens),
never assumed from `first..last` without checking every extension in between resolved to
a real file. A silently-non-contiguous range would be worse than the status quo it
replaces — it would claim completeness it does not have.

## Consequences

- **Breaking change to the URI scheme.** `PathSpec`'s canonical URI carries a
  documented "crown-jewel round-trip invariant" — this rename breaks any already-
  serialized `os:` locator (saved sessions, exported case-file provenance records).
  Needs either a one-time migration of any persisted locators, or a decode-side
  compatibility arm accepting `os:` as a deprecated alias for one release, TBD at
  implementation.
- **Zero semantic change for single-file sources** (raw `.dd`, `.vmdk`, `.vhd`, …) —
  they get `file:<path>` with no segment range, exactly today's `os:<path>` renamed.
- **Human `Display` rendering benefits independently and immediately** — regardless of
  when the canonical-URI rename lands, a report can already render "Exhibit:
  DESKTOP-SDN1RPT (4 segments, `.E01`–`.E04`)" by asking the opened reader how many
  segments it actually used, sourced from the `File` layer plus case-file context —
  the same lossless-machine-form / lossy-human-`Display` split the address design
  already establishes for volume labels (`universal-address-design.md` §2.3).
- **No change to `PersistentAddress`, `VolumeId`, or any identity key** — this ADR is
  entirely inside the locator (`PathSpec`/`uri.rs`); the `[P]` identity design (ADR
  [0009](0009-fileid-in-forensicnomicon-core.md) and the address design doc) is
  untouched.
- **"Exhibit" terminology stays out of `Layer` entirely.** A prior discussion
  considered naming this layer `exhibit:` directly; rejected because not every
  `PathSpec` root is a top-level evidentiary exhibit with its own custody history
  (`Vfs::open_source` seeds a bare `Layer::Range` root for a carved/nested/in-memory
  source that was never independently acquired) — conflating a mechanical locator
  token with a custodial/labeling concept repeats the exact mistake the address
  design already corrected elsewhere ("labels are display metadata everywhere —
  outside every identity-bearing type"). Exhibit numbering belongs in the case
  file's provenance layer that *wraps* a `PathSpec`, expressed via `Display`, not in
  the `Layer` enum.

Implementation not yet started; this ADR records the naming decision ahead of the code
change.

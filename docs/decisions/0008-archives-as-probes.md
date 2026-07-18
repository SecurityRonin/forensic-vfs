# 0008 — Archives resolve as a first-class ArchiveOpen layer

**Status:** Accepted (contract); adapter wiring is a follow-on (no functional gap today)

## Context

A consumer that reads an evidence image must not know one packing format from
another: `case.E01.gz` should resolve identically to `case.E01`, and
`case.tgz`/`case.zip`/`case.7z` should surface their inner evidence the same way a
GPT partition or a BitLocker volume does. Today that peeling lives in
`archive-core` (`peel_archive`), which `disk-forensic` and `4n6mount` call *before*
handing bytes to the VFS. That works, but it is a second, parallel detection
on-ramp bolted in front of the resolver — the exact "N parallel detection stacks
in N consumers" smell the VFS abstraction exists to remove.

The question this ADR settles: **how do archives become a first-class VFS layer so
they ride the same recursive `resolve()` as every other layer — without dragging a
single decoder or compression dependency into the zero-dependency leaf?**

Two facts from the settled post-engine-retirement architecture (ADR 0007, commit
`96976d6`) shape the answer:

1. The generic resolver now lives in `crates/core` (`resolve.rs`). It descends
   **container → volume → filesystem** layers recursively, re-sniffing each decoded
   `DynSource` a `ContainerOpen::open` returns (`resolve.rs:133-143`). Container
   recursion is already automatic.
2. The VFS is **one-trait-per-layer**, and each layer's trait is named for its primary
   `open()` method (the `Read`→read / `Write`→write idiom): `ContainerOpen`,
   `VolumeSystemOpen`, `EncryptionOpen`, `FileSystemOpen` (plus the `Registry` dispatch
   table) live in the leaf; the *concrete* probers and `default_registry()` live in the
   consumer/orchestration layer, **outside** the leaf's dependency graph. Each `*Open`
   trait has two methods that are its two steps — `probe()` recognizes (dispatch), `open()`
   peels/decodes — so the archive layer deserves its own.

## Decision

**Archives are a first-class layer with their own leaf trait, `ArchiveOpen`** — one
trait for the archive layer, matching every other layer's single `probe() + open()`
shape. This revises the earlier framing of this ADR ("archives need no new trait";
gz/bz2 mapped onto `ContainerOpen`, tar/zip/7z onto `FileSystemOpen`, and `.tgz` was
an emergent `GzipDecoder ∘ TarProbe` composition); git history holds that original. Three
reasons drove the change:

1. **One-layer-one-trait consistency.** The VFS gives container, volume, encryption, and
   filesystem each their own probe trait; the archive layer is a peer and deserves the
   same, not a mapping split across two unrelated traits.
2. **Dev / AI-agent UX.** One elegant archive entry point (`archive_core::open` / a single
   `ArchiveOpen`) is discoverable and teachable; a gz-here / tar-there split is not.
3. **The crate owns `.tgz` combo knowledge in one place.** gz+tar / bz2+tar belong to the
   archive crate, not to an emergent property of layer composition the resolver arranges.

`ArchiveOpen` is a leaf trait with the same two-method shape as its peers:

```rust
trait ArchiveOpen {
    fn probe(&self, window: &SniffWindow) -> Confidence;
    fn open(&self, src: DynSource) -> VfsResult<ArchiveContents>;
}

enum ArchiveContents {
    Stream(DynSource),     // 1→1: a bare gz/bz2 wrapper; the decoded source
                           //      re-enters `resolve()` exactly like a decode
    Members(Vec<Member>),  // 1→N: tar/zip/7z; each member's `source_for(member)`
                           //      re-enters `resolve()`
}
```

- **Bare compression wrappers (gzip, bzip2) → `ArchiveContents::Stream`** (1→1). `open` peels
  the outer stream to the inner `DynSource`; the resolver re-sniffs it, so
  `E01.gz → E01 → GPT → NTFS` collapses in a single `resolve()` call, identically to
  `E01 → GPT → NTFS` — the peel re-enters resolution just like a container decode.
- **Multi-member archives (tar, zip/`.clbx`, 7z) → `ArchiveContents::Members`** (1→N). `open`
  returns the member table; a member that is itself evidence (an `E01` inside a `.zip`) is
  reached by `source_for(member)` and re-entering `resolve()` on that member's `DynSource`.
- **`.tgz`/`.tbz2` are handled INSIDE the probe.** gz+tar and bz2+tar are the archive
  crate's own combo knowledge — a single fused streaming peel (see the O(n) requirement
  below), not an emergent `GzipProbe ∘ TarProbe` chain the resolver composes. The crate
  owns the combination in one place.

**The resolver gains a dedicated archive descent.** Alongside its container / volume /
encryption / filesystem descents, `resolve()` tries the registered `ArchiveOpen`s:
`ArchiveContents::Stream` → recurse on the decoded source; `ArchiveContents::Members` → each
member re-enters `resolve()`. Archives resolve as a peer layer, not bolted in front of the
resolver.

**The leaf stays a pure contract.** The only leaf change is additive and non-breaking: the
`ArchiveOpen` trait + `ArchiveContents` type — no decoder, no dependency. `FsKind` needs no
change and archive member trees no longer masquerade as filesystems, so the old
`FsKind::from("tar" | "zip" | "7z")` mapping is retired. Every concrete decoder and its
heavy dependencies (flate2, bzip2-rs, tar, `zip-forensic-core`, sevenz-rust2) live in an
`archive-core` adapter behind a feature gate — never in the leaf. The consumer's
`default_registry()` registers the one adapter through a new `.archive(...)` builder:

```rust
Registry::new()
    // …existing container/volume/encryption/filesystem probers…
    .archive(archive_core::vfs::ArchiveAdapter)   // one ArchiveOpen: gz/bz2 + tar/zip/7z (+.tgz/.tbz2)
```

## Consequences

- **One detection on-ramp.** Once the adapter is registered, `disk-forensic` and
  `4n6mount` drop their pre-resolver `peel_archive` call: `resolve()` peels archives
  as ordinary layers, so every current and future VFS consumer gets archive
  transparency for free, with no per-consumer archive code.
- **Zero dependency inversion.** The dependency arrow stays pointed *down onto* the
  leaf. archive-core (and its compression deps) is registered *by* the consumer; the
  leaf gains only the `ArchiveOpen` trait + `ArchiveContents` type.
- **`forbid(unsafe)` is preserved end-to-end.** The leaf gains only a trait and a type
  (no unsafe); archive-core is already `forbid(unsafe)`; the adapter adds no unsafe.

### Peeling MUST be O(n) single-pass streaming (requirement, not a tradeoff)

`tar xzf` *streams*: gunzip pipes into tar member-by-member in one pass, holding ~nothing
between them. A naive layered realization cannot — if `ArchiveOpen::open` had to
return a fully random-access `DynSource` over the decompressed tar, a bare-gz `Stream`
peel would materialize the **entire** decompressed tar (in RAM/temp, or behind a zran
index that still scans it all) *before* the tar walk seeks within it: intermediate cost
proportional
to the whole decompressed tar. That is rejected. **The archive layer peels in one O(n)
pass and spills only the inner evidence to temp** — never the whole decompressed tar.

Decompose the cost honestly. Three parts, and only one is avoidable:

- **Decompression: one pass, O(n) in the compressed bytes** — unavoidable, but done
  *once*, streaming, never re-scanned.
- **Temp for the inner evidence: O(evidence)** — unavoidable, because random-access
  forensic analysis (NTFS/GPT seeking all over an `E01`) requires the evidence bytes to
  land somewhere seekable. Temp holds only the target member(s), not the archive.
- **The whole decompressed tar: O(whole tar)** — *this is what we eliminate.* A fused
  gunzip→untar pass classifies members by name/magic as it streams and writes only the
  matching evidence member(s) to temp (`case.E01`, or every `.E0N` of a segment set),
  skipping the rest. RAM stays O(1).

So the realization is a **fused streaming decoder**, not the naive composition. The
determination "tgz = gzip+tar" stays the conceptual *model*; the *implementation* is a
single pass that decompresses and selects in lock-step, giving O(n) time, O(evidence)
temp, O(1) RAM. `resolve()` then re-enters on the temp-backed `DynSource` (→ GPT → NTFS)
for the random access that forensic analysis needs — paid once, against the temp file,
not by re-decompressing on every seek.

Implementation consequence (tracked, not deferred as optional): `archive-core`'s peel is
today in-memory with a hard output cap. It must move to **streaming temp-spill** —
`peel_archive` returns a temp-backed seekable handle rather than an in-memory `Vec<u8>`,
one decompression pass, member-selective. Both consumers (`disk-forensic`, `4n6mount`)
already stage peeled evidence to temp before analysis, so the seam is an API shape change
(temp handle vs `Vec<u8>`), not new behavior downstream. This is the O(n) requirement
this ADR commits to, not a "when profiling hurts" nicety.

### Two-phase realization: Detect → `AccessPlan` → Peel

The O(n) requirement and the member-set classification below are both delivered by one
structural move: split the archive probe into two phases, which is just the leaf's own
`probe`/`open` split made explicit with a richer phase-1 output.

- **Phase 1 — `detect(source) -> AccessPlan` = `probe`, bounded and content-authoritative.**
  Peeks *one* decompressed block per compression layer (a bounded head — sized to the
  resolver's `SNIFF_CAP`, ~40 KB, which reaches the deepest magic, ISO 9660's `CD001` at
  32769) and reads only the archive's member *table* (zip EOCD / 7z header / tar headers). It
  **never inflates a payload**, and it is **name-free** — every classification is decided by
  bytes (see the five rules below). It classifies the most direct route to the evidence.
- **Phase 2 — `peel(source, plan) -> DynSource` = `open`, executes the chosen strategy.**

```rust
enum AccessPlan {
    Direct,                                            // raw dd / already a disk image
    Wrapper    { codec: Codec, access: Access },       // bare gz/bz2 over one stream
    Member     { format, index, name, access: Access },// one forensic file in an archive
    SegmentSet { format, members: Vec<Segment>, kind },// E01/E02…, split .001/.002, split VMDK
    Collection { format },                             // several independent items → a tree
}
struct Segment { name: String, index: usize, access: Access } // per-segment access
enum Access {
    InPlace { offset, len },  // Stored/uncompressed member → seek a sub-range in place (zero-copy)
    Zran,                     // Deflate/Deflate64/gzip → checkpoint seek-index, random access, no full inflate
    SpillToTemp,              // non-seekable codec (LZMA/7z) or tiny → decompress once to temp
}
```

**`Access` is per member *and* per segment — `SegmentSet` composes with `Zran`.** Each
`Segment` carries its own `Access`, so a segmented E01 set inside a zip where the members
are Deflate-compressed gets **per-segment zran** random access: the reassembled logical
image dispatches a read at logical offset *O* to `(segment k, local offset)` and satisfies
it via segment *k*'s `Access` — a `Zran` checkpoint seek into that deflated member (no full
inflate), an `InPlace` sub-range for a `Stored` member (zero-copy), `SpillToTemp` only for a
non-seekable codec. So a fully-Deflate segmented `E01`/`E02`/`E03`-in-zip is randomly
accessible with only the per-segment checkpoint indexes in RAM — **zero temp spill, O(1)
inflate per seek** (bounded by the checkpoint interval). Reassembly (ewf `SegmentBacking`)
never means "extract every segment to temp first."

**Why the split is structural, not cosmetic.** Phase 1 is *typed* to see only bounded heads
plus member tables, so it **cannot** accidentally inflate a payload to classify — the
whole-stream inflate exists only inside a deliberately-chosen `SpillToTemp` execution. This is
the general form of "don't uncompress the whole `bz2` just to check the tar magic," and it is
what makes the O(n) requirement above a property of the *types*, not of programmer discipline.

**Content-authoritative detect — five rules.** `detect` decides everything from bytes; the
file name is not an input to any classification.

1. **Magic decides membership both ways.** Every codec/container magic sits at a fixed offset
   (gzip `1F 8B`@0, bzip2 `BZh`@0, zip `PK`@0, 7z `37 7A BC AF 27 1C`@0, tar `ustar`@257). Its
   *presence* confirms the format; its *absence rules the format out*. A name claiming a format
   whose magic is absent is not "unverified" — it is a claim that can only fail at decode, so the
   name adds nothing on either path.
2. **The peek-decode is the coincidental-magic guard.** A raw disk that merely starts with
   `1F 8B`/`BZh` but isn't really compressed *fails to decode* the bounded head → `Direct` (not
   packed). This is a content guard; the old name-based "must have a compression ext" guard is
   retired.
3. **The peek runs the *full* probe set, for positive identification.** The decompressed head
   becomes a `SniffWindow` fed to every registered probe — not just a tar check. `ustar`@257 is
   one probe beside the volume/filesystem probes (MBR `55 AA`@510, GPT `EFI PART`@512, NTFS@3,
   ext `0xEF53`@1080, APFS `NXSB`@32, HFS+@1024, ISO `CD001`@32769). So the answer is *positive*
   ("the inner is a GPT disk / NTFS volume / nested zip / tar / unknown"), not "not a tar." This
   is literally the recursive `resolve()` re-sniff; **archive-core owns packing detection only**,
   and the forensic magics stay in the VFS volume/filesystem probes (knowledge from
   forensicnomicon) — archive-core grows no filesystem knowledge.
4. **Prefer the most-seekable `Access` the codec allows — everywhere, not one case.** The ladder,
   best first: `Stored`/uncompressed → `InPlace` (zero-copy sub-range); a seekable codec (Deflate,
   Deflate64, gzip) → `Zran` (checkpoint index, random access, no full inflate); a non-seekable
   codec (LZMA/LZMA2/7z, and bzip2 until a block-index lands) → `SpillToTemp` (last resort). The
   choice is made **per item and per segment**, so a mixed archive uses all three side-by-side
   rather than forcing the worst case on everything. `Zran` therefore covers a bare `.gz` of a raw
   disk, every Deflate/Deflate64 member in a zip, and a `.tar.gz` single member (gzip zran + the
   tar header's decompressed offset ⇒ seek straight in) — not just the last of those. The ladder
   admits more seekable codecs (bzip2 block-index, seekable zstd, xz blocks) as their indexes are
   added, with no model change.
5. **The name is absent from detection; irreducible only for split-multipart *ordering*.** The
   one thing content cannot supply is the order of a linkage-free split — `{disk.001, disk.002,
   disk.003}` are structureless byte ranges with nothing inside saying "part 2 of 3," so the
   numeric suffix *is* the reassembly data for `SegmentSet { kind: SplitRaw }` (and
   filename-referenced extents like VMDK descriptors). EWF is the reducible counter-case: `.E0N`
   segments carry an internal segment-number + set-GUID, so ewf groups/orders by content and the
   `.E0N` name is only a candidate-finding heuristic. Beyond split ordering, the name survives
   solely as a non-correctness **display label** in reports.

**The three member-set cases below become `AccessPlan` variants,** so classification happens
once, in phase 1: one evidence member → `Member`; independent items → `Collection`; a segmented
image → `SegmentSet`. Access strategy is chosen from the member table without decompressing: a
`Stored` E01-in-zip → `InPlace` (zero-copy random access); a `Deflate`/`Deflate64` E01-in-zip →
`Zran` (random access with no full inflate — reusing `zip-forensic-core`'s `DeflateSeekReader` /
`deflate64_seek`); an LZMA/7z member → `SpillToTemp`. `SegmentSet` execution reassembles the
split image via the container reader's sibling backing (ewf `SegmentBacking`). The
`ArchiveOpen` surface is unchanged — `detect`/`peel` is the *internal* realization of the
archive adapter's `ArchiveOpen::open`, its `AccessPlan` the richer phase-1 form of `probe`.

### One open detail for the wiring PR — how many logical images an archive holds

"Archive → member list" is not the whole story: what a consumer wants out of an archive
depends on how its members relate, and there are **three** cases. Phase-1 `detect`
classifies which before `peel` executes (see the `AccessPlan` variants above):

1. **One evidence member** (`case.zip` holding only `case.E01`). `detect` → `Member`;
   `ArchiveContents::Members` yields the single member, whose `source_for(member)` re-enters
   `resolve()` and collapses `case.zip → E01 → GPT → NTFS` in one pass. With a single
   archive descent there is no filesystem-before-container ambiguity to arbitrate — the old
   "does a `FileSystemOpen` mount a one-entry tree instead of collapsing?" question
   disappears under the unified `ArchiveOpen`.

2. **Several independent evidence items** (a zip of unrelated `a.E01`, `b.vmdk`, `c.dd`).
   `detect` → `Collection`; `ArchiveContents::Members` hands back the whole set, and each member
   re-enters `resolve()` on its own.

3. **A segmented set that is ONE logical image** (`{case.E01, case.E02, … case.E0N}`, or
   split raw `.001/.002…`, or split VMDK `disk-s001.vmdk…` + descriptor). `detect` →
   `SegmentSet`. The members are *not* independent — the EWF reader given `case.E01` must
   read `case.E02/.E03` to reconstruct one stream, and those siblings live *inside the same
   archive*. `ArchiveOpen::open` returns the member list, but the segment reader opened over
   the `.E01` member needs a path to its siblings: `peel` binds a **sibling-member provider**
   to the archive — exactly the seam `ewf`'s `SegmentBacking` already provides for on-disk
   `.E01/.E02` and for E01-in-zip (the cross-format `open_zip` work). The reassembled logical
   `DynSource` then re-enters `resolve()` → GPT → NTFS as usual.

Consequence for the contract: all three cases ride the archive descent; **case 3
additionally binds the segment reader's sibling-backing inside `peel`**, reusing the
container reader's existing multi-segment seam. The one leaf addition is the `ArchiveOpen`
trait itself — and this is why the adapter must classify member sets (phase-1 `detect`)
before deciding stream vs member-tree vs reassemble.

### Implementation status

The contract is **defined and settled by this ADR**; the leaf's `ArchiveOpen` trait +
`ArchiveContents` type, the resolver's archive descent, and the archive-core `vfs` adapter
(one `ArchiveOpen`) are a follow-on landing in the **0.4 fleet cut** (which also renames
all five layer traits to the `*Open` form — container/archive/volume-system/encryption/
filesystem each become `*Open`, unifying every layer on `probe() + open()`). There is **no
functional gap**
meanwhile — `disk-forensic` and `4n6mount` already peel via
`archive_core::peel_archive`, verified against their suites. This ADR replaces the
earlier "hold until the engine retirement settles" note (the retirement has landed):
the seam is now buildable whenever the adapter work is scheduled, against a registry
that has stopped moving.

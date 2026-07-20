# 0011 — ImageSource as a first-class resolver terminal (medium-agnostic archive unwrap for memory/log)

**Status:** Proposed

## Context

`forensic-vfs` already gives *disk* evidence transparent, recursive archive
unwrap. The resolver (`crates/resolver/src/lib.rs`,
`SourceOpen::open_with_credentials`) sniffs a `DynSource`, and descends
filesystem → volume-system → encryption → container → archive layers, re-entering
itself on every peeled source (`lib.rs:142-232`). ADR 0008 made archives a
first-class layer: a bare `gz`/`bz2` peels to `ArchiveContents::Stream(inner)` and
`inner` re-enters resolution exactly like a decoded container
(`lib.rs:206-214`); a multi-member `zip`/`7z`/`tar` peels to a member table whose
members each re-enter (`lib.rs:215-226`). So `case.E01.gz` and
`case.zip → case.E01 → GPT → NTFS` collapse in one `open()` call.

The question this ADR settles: **should a memory dump packaged the same way —
`memory.raw.gz`, `memory.zip`, `dump.7z`, even `memory.raw.zip.zip.7z` — ride that
same recursive peel, so a memory reader receives the raw physical-page byte stream
without any consumer re-implementing archive detection?**

Two facts from the code shape the answer, and they pull in opposite directions:

1. **The peel is already medium-agnostic.** Every layer speaks one edge:
   `ImageSource` (`crates/core/src/source.rs:123`), a positioned-read
   `read_at(offset, buf)` byte stream, `Send + Sync`, no writer
   (`source.rs:123-152`). An archive peel produces a `DynSource`
   (`Arc<dyn ImageSource>`, `source.rs:158`) via `ArchiveContents::Stream(DynSource)`
   (`crates/core/src/archive.rs:18`). Nothing about that peel knows or cares whether
   the bytes it hands back are a disk image, a memory dump, or a log. A raw memory
   dump unwrapped from its packaging **is** just a `DynSource`.

2. **The resolver's *terminal* is filesystem-only.** `open_with_credentials`
   returns `Option<Resolved>`, and `Resolved` mandates a mounted filesystem:
   `pub fs: forensic_vfs::DynFs` is not optional (`resolver/lib.rs:63-72`). The only
   way the recursion returns `Some` is the filesystem branch (`lib.rs:142-156`);
   every other branch either recurses or falls through. So when
   `memory.raw.gz` peels to a raw memory `DynSource` and that source re-enters
   resolution, **no filesystem prober matches, and the resolver returns `Ok(None)` —
   discarding the peeled memory source it just produced.** The medium-agnostic peel
   runs correctly and then throws its result away, because the only terminal that can
   *keep* a source is "a filesystem mounted."

Meanwhile the memory reader has no seam to receive a `DynSource` even if the
resolver offered one. `memf-format`'s public API is **path-based**:
`FormatPlugin::open(&self, path: &Path)` and `open_dump(path: &Path)`
(`memory-forensic/crates/memf-format/src/lib.rs:179,189`), and `open_dump_inner`
opens a `std::fs::File` by path (`lib.rs:205`). Its read edge is a *distinct*
positioned-read trait, `PhysicalMemoryProvider::read_phys(addr, buf)`
(`lib.rs:106`), which addresses *physical* memory (gapped, format-aware ranges) —
not the flat file-offset `ImageSource::read_at`. Today, archive handling for memory
is the extract-to-temp-then-open-by-path detour: `open_dump_with_raw_fallback`'s own
doc says it exists for a dump "extracted from an archive with known dump extensions"
(`lib.rs:193-201`). That is a second, parallel archive on-ramp bolted in front of the
memory reader — the exact "N parallel detection stacks in N consumers" smell the VFS
abstraction was built to remove (ADR 0008 Context).

The architectural observation: a **memory-dump-format parser is to a raw dump
`DynSource` what a filesystem is to a disk `DynSource`** — a medium-specific
interpretation layered over the same medium-agnostic byte edge. The resolver
already owns the disk terminal (mount a filesystem). Memory (and log) want the
*symmetric* terminal over the *same* peeled `DynSource`. The peel is shared; only
the terminal differs.

## Decision

**Make "produce a fully-peeled raw `ImageSource`" a first-class resolver terminal,
orthogonal to the downstream medium.** Route memory input through the same
recursive archive/compression peel the disk path uses, terminating at "hand the raw
`DynSource` to `memf`" (which then detects LiME / AVML / hiberfil / crash-dump /
raw) rather than at "mount a filesystem."

Two seams, both small and additive:

### 1. A source terminal in the resolver (`forensic-vfs-resolver`)

Add a sibling entry point to `SourceOpen` that runs the **medium-agnostic descent
only** — archive peel (ADR 0008) plus, where present, a bare container decode — and
returns the peeled source instead of requiring a filesystem:

```rust
pub struct ResolvedSource {
    pub source: DynSource,   // the fully-unwrapped raw byte edge
    pub spec: PathSpec,      // its locator (archive-member / container layers recorded)
}

pub trait SourceOpen {
    // existing:
    fn open(&self, source, spec, depth) -> VfsResult<Option<Resolved>>;         // disk: → filesystem
    // new:
    fn resolve_to_source(&self, source, spec, depth) -> VfsResult<ResolvedSource>; // any medium: → raw DynSource
}
```

`resolve_to_source` peels the archive/compression layers recursively (the loop at
`lib.rs:204-232`, factored out) and returns the innermost `DynSource` that no
further *packaging* layer claims. It does **not** run the filesystem, volume, or
encryption-into-filesystem descent — those are disk interpretation, not unwrap. The
existing `open()` is then re-expressed as `resolve_to_source()` followed by the
disk fs/volume descent over the result. The filesystem terminal becomes *one
consumer* of the source terminal, not the only terminal.

For a single-member archive the terminal returns that member's source; for a
`Collection` (several independent items) memory input is out of scope — a memory
sweep is given a single dump, so `resolve_to_source` yields the one evidence
member and reports ambiguity loudly if the archive holds several unrelated dumps
(it never silently picks one). `SegmentSet` does not arise for memory dumps
(they are single-stream, not `.E01/.E02`-segmented).

### 2. A `DynSource` consumption seam in `memf-format`

`memf` gains a reader-based open beside the path-based one, so a provider reads its
dump bytes from a `DynSource` (via `ImageSource::read_at`) instead of a `File`:

```rust
pub trait FormatPlugin {
    fn probe(&self, header: &[u8]) -> u8;
    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>>;      // keep
    fn open_source(&self, src: DynSource) -> Result<Box<dyn PhysicalMemoryProvider>>; // add
}
pub fn open_dump_source(src: DynSource) -> Result<Box<dyn PhysicalMemoryProvider>>;
```

`memf`'s format detection and physical-range logic are unchanged — only the byte
source moves from `File` to `DynSource`. `PhysicalMemoryProvider` stays memf's own
edge: it maps a *physical* address to a file offset and reads that offset from the
`DynSource`. The two positioned-read traits stay correctly layered — `ImageSource`
= "the raw dump file's bytes" (flat), `PhysicalMemoryProvider` = "physical RAM"
(gapped, format-aware) — exactly as a filesystem's node reads layer over
`ImageSource` on the disk side.

The wiring (in `issen` / the memory front-end) becomes: `resolve_to_source(path)` →
`open_dump_source(resolved.source)`. No consumer re-implements archive detection;
the extract-to-temp detour behind `open_dump_with_raw_fallback` is retired in favor
of the resolver's `SpillToTemp` access plan, which the resolver already owns.

### What this does NOT change

- **The archive peel itself.** It already exists in `archive-core` and resolves as
  a first-class layer (ADR 0008). This ADR reuses it; it adds no decoder.
- **The `ImageSource` contract leaf.** `resolve_to_source` and `ResolvedSource`
  live in `forensic-vfs-resolver` (the evolving-detection crate), not the frozen
  leaf. The leaf gains nothing.
- **memf's format detection, `PhysicalMemoryProvider`, and physical addressing.**
  Only the byte source changes.
- **The disk path.** `open()` keeps its behavior; it is re-expressed over the new
  terminal but its result and consumers are identical.

## Consequences

- **One archive on-ramp for every medium.** Disk, memory, and (future) log readers
  share one recursive peel. A new packaging format added to `archive-core` benefits
  all of them at once; a memory consumer never grows archive code.
- **Zran-capable memory unwrap.** A `gz`/`Deflate`-packaged dump gets random-access
  reads through the resolver's `Zran` access plan (ADR 0008), so memf's scattered
  `read_phys` (page-table walks jump around) are satisfied by checkpoint seeks with
  **no full inflate and no temp spill** — strictly better than today's mandatory
  extract-to-temp.
- **The resolver stops discarding non-disk sources.** The `Ok(None)`-drops-a-peeled-
  memory-source behavior (Context fact 2) is fixed structurally: the peeled source is
  a returnable terminal, not a dead end.
- **`forbid(unsafe)` preserved.** New code is a trait method, a struct, and a
  provider that reads via `read_at`; no unsafe, no new dependency in the leaf.
- **Cost:** a non-seekable codec (`7z`/LZMA) still forces a full-dump temp spill —
  see the cost model; this ADR does not make LZMA seekable, it routes to the same
  `SpillToTemp` plan the disk path uses.

## Alternatives considered

### A. Status quo — memf takes a pre-peeled path; each consumer extracts to temp

The current model (`open_dump_with_raw_fallback`, `lib.rs:193-201`): the consumer
peels an archive to a temp file and opens it by path. **Steelman:** it works today,
it is simple, and deep memory nesting is rare (`memory.raw.gz` is common;
`memory.raw.zip.zip.7z` is essentially never seen in the field). **Why rejected as
the *default*:** (1) it duplicates archive detection per consumer and re-implements
what `archive-core`/the resolver already own (DRY violation, the ADR-0008 smell);
(2) it *always* spills to temp — a `gz`/`zip` dump gets a needless full-size temp
copy where Zran would avoid it (a 32 GB dump ⇒ 32 GB of avoidable temp per run);
(3) it handles single-layer only — a responder who wrapped a vendor `.gz` inside a
`.zip` breaks it unless the consumer loops, and a hand-rolled loop materializes
every intermediate. The resolver gives Zran-when-possible plus uniform nesting for
free. Status quo remains the correct *fallback execution* (it is exactly
`SpillToTemp`); it is the wrong *architecture*.

### B. A `MemoryDumpOpen` resolver mount terminal (full symmetry with `FileSystemOpen`)

Add a `MemoryDumpOpen` prober trait to the vfs `Openers` registry, symmetric to
`FileSystemOpen` (`registry.rs:169`), and make `Resolved` an enum (`Fs | Memory |
Log`) so the resolver *mounts* the dump like it mounts a filesystem. **Attraction:**
maximal one-layer-one-trait consistency. **Why rejected:** it drags memory-format
knowledge into the vfs registry, violating the layer split (memf owns memory
knowledge; the leaf owns only the byte edge and the disk-oriented probe traits — the
"knowledge lives with the parser" rule). It forces `Resolved` into a breaking enum
change and makes the leaf/registry aware of every medium. Alternative Y (the chosen
`resolve_to_source` terminal + memf-side detection) achieves the same transparency
with the medium knowledge staying in memf, and matches the thesis literally: "hand
the raw `ImageSource` to memf, which detects the format." Reconsider B only if a
third and fourth medium make a registry-driven dispatch pay for itself.

### C. Do nothing for nesting; add only single-layer `gz` support to memf

Teach memf to peel a bare `gz`/`zip` itself and stop. **Why rejected:** it re-adds
the parallel on-ramp (worse — now memf carries compression deps), and it forecloses
nesting arbitrarily. The resolver seam costs about the same and is complete.

## Cost model — access characteristics for large dumps

Memory dumps are frequently 8–64 GB, so the codec the dump is packaged with
dominates temp and RAM cost. The resolver's `AccessPlan`/`Access` ladder (ADR 0008)
decides per layer; the table below is that ladder applied to a single-member dump.

| Packaging | Access plan (ADR 0008) | Random access? | Temp spill | RAM | Notes |
|---|---|---|---|---|---|
| `memory.raw` / `.dd` | `Direct` | yes (native) | none | O(1) | already a flat source |
| `memory.raw.gz` | `Zran` | yes (checkpoint seek) | **none** | O(index) | why memf-on-gz is viable — no full inflate |
| `memory.zip` (Stored member) | `InPlace` | yes (zero-copy sub-range) | none | O(1) | seek a sub-range in place |
| `memory.zip` (Deflate member) | `Zran` | yes (checkpoint seek) | **none** | O(index) | matches the memf-on-zip validation this session |
| `dump.7z` / `.xz` (LZMA) | `SpillToTemp` | via temp only | **O(dump)** | O(1) | LZMA is not seekable → full-size extract once |
| `memory.raw.zip.zip.7z` | worst layer wins | via temp only | **O(dump)** | O(1) | see below |

`Zran` index size is the checkpoint interval trade: at a 4 MB interval a 32 GB dump
carries ~8 K checkpoints (tens of MB of index) and bounds re-inflate to one interval
per seek — cheap against memf's scattered reads. `SpillToTemp` for a 32 GB LZMA dump
means a one-pass 32 GB decompression to a 32 GB temp file, then random access against
the temp. RAM stays O(1) in every row; the differentiator is temp.

**Memory loses the disk path's member-selectivity.** On disk, `SpillToTemp` writes
only the evidence *member* of a multi-member archive (`case.E01`, not the whole
decompressed tar — ADR 0008 "Peeling MUST be O(n)"). For memory the dump **is** the
single member, so `SpillToTemp` necessarily spills the whole dump — there is no
smaller thing to select. The Zran rows are therefore where the win lives; the LZMA
row is genuinely as expensive as today's extract-to-temp (it *is* that, routed
through the resolver).

**Nesting cost = the least-seekable layer in the chain.** For `A.gz` inside `B.7z`,
peeling the outer `7z` is `SpillToTemp` (materialize the whole inner `A.gz` to
temp), then the inner `gz` is `Zran` over that temp. The effective plan is the
worst (least-seekable) layer, and each non-seekable layer forces a full-size
materialization of *its* output. So a dump wrapped in any LZMA layer pays a
full-dump temp regardless of the other layers — nesting does not compound RAM, but a
single LZMA layer anywhere caps the whole chain at `SpillToTemp`. This is the
general form of ADR 0008's "don't materialize the whole decompressed tar," and for
single-member memory it has no selectivity escape hatch.

Practical guidance surfaced by the model: **recommend responders package memory
dumps with `gz`/`Deflate`, not `7z`/`xz`**, precisely so the resolver can Zran them
without a second full-size copy. That guidance is a *consequence* the design makes
legible; it is not a constraint the design imposes.

## Open questions

1. **Where exactly does `resolve_to_source` stop?** After archive + bare-container
   peel, but the ordering of container-vs-archive and whether an encryption layer
   can wrap a memory dump (a dump on a decrypted volume image is contrived but not
   impossible) needs a decision. Proposed: `resolve_to_source` runs archive descent
   only for the memory/log path; disk keeps the full descent. Confirm no real
   memory-in-container case is foreclosed.
2. **`Collection` disambiguation for memory.** If an archive holds several dumps (a
   `DC01.mem` and a `WS.mem` in one `.zip`), does the memory front-end enumerate and
   run each, or error? Proposed: enumerate and run each (a memory-side `Collection`
   consumer), mirroring issen's multi-source ingest — but that is a front-end policy,
   not a resolver one.
3. **Do we also retire the path-based `open_dump` once `open_source` lands,** or keep
   both? A live-system dump acquired to a local path never needs the resolver; keeping
   the path API avoids a needless `DynSource` wrap for that common case. Proposed:
   keep both; `open_source` is the archive/remote path, `open_dump` the local-file
   fast path.
4. **Log medium.** The same terminal serves a `.evtx.gz` / `journal.zip`, but log
   readers have their own (record-cursor) edge. Is `resolve_to_source` sufficient for
   them, or do they want the member *table* (a `Collection` of rotated logs) rather
   than one stream? Likely the former for a single log, the latter for a rotation set
   — out of scope here, flagged for a log-specific ADR.

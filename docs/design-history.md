# Design History — Prior-Art Survey & Adversarial Review Log

The **canonical, current design** of the universal forensic VFS is the
[README](https://github.com/SecurityRonin/forensic-vfs#readme), the ADRs under
[`docs/decisions/`](decisions/), and the [PRD](PRD.md); the terse contract tour is
[`architecture.md`](architecture.md).
This page preserves two pieces of the *origin* design doc that those documents do
not carry and that remain worth keeping for provenance: the **prior-art survey**
(how the design borrows from and differs from dfVFS, Velociraptor, TSK, dissect,
and libvshadow) and the **adversarial review log** (the two hostile-critic rounds
that shaped the contracts). The origin doc lived in the `disk-forensic` repo and
was removed once its current-state content moved here and into the ADRs; git
history retains the full original.

---

## Prior art — what's borrowed, what's distinct

Borrowed, deliberately: recursive path-spec (dfVFS / Velociraptor), image → volume-system → filesystem → file layering + `img_info` read-callback (TSK), loader auto-detect + `map` (dissect), VSS-volume-of-stores + encryption layers (libvshadow / dfVFS BDE/LUKSDE), the `trait SeekAndRead` / blanket-impl object-safety pattern (Rust `vfs`).

Distinct capabilities:

- **Read-only by construction, not convention.** The byte-source trait has no write method; immutability is a type property, not a documented promise. dfVFS / TSK / dissect are read-only by discipline; here a write is uncompilable.
- **`&self` positioned-read parallel core.** `read_at(&self)` + `Send + Sync` + a concurrent cache gives lock-free-hot-path parallel reads over one shared stack — the Python references are single-reader-per-handle; TSK / libbfio are `Seek`-cursor based.
- **Snapshots as typed first-class sub-volumes** bound to `state-history-forensic::TemporalCohort<H>` — a snapshot is a `Volume` with an `EpochTag`, so time-travel composes with the same navigation and correlation.
- **One unified metadata + findings model** across container / volume / encryption / filesystem: every layer emits `forensicnomicon::report::Finding`; `FsMeta` carries per-timestamp source/resolution provenance and the name/meta allocation split in one record.
- **Self-describing locator + serde, credentials out-of-band.** A `PathSpec` carries its whole open-recipe and round-trips through a report, session, or evidence row, while credentials stay out of the serialized address (fixing dfVFS's global-keychain footgun without leaking keys into reports).
- **One detection engine for the whole fleet** (`4n6mount`, `issen`, `disk4n6` share one `Vfs`), replacing three parallel detect/dispatch implementations.

---

## Adversarial review log

The contracts were hardened over two independent hostile-critic rounds. Recorded honestly: round 1 ran with **Gemini 3.1 Pro (High)** (and Grok as a second voice) because the requested reviewer was rate-limited at the time; round 2 ran with **Codex (GPT-5)** as the requested reviewer on the round-1-revised design, tasked to find what round 1 *missed* or what its fixes *broke*.

### Round 1 — Gemini 3.1 Pro (High)

| # | Critique | Resolution |
|---|---|---|
| 1 | `as_slice(&self) -> Option<&[u8]>` unsound over an LRU cache (borrow tied to `&self`, but cache access mutates/locks). | **Accepted.** Replaced with `view() -> Option<SourceView<'_>>`, a guard owning an `Arc<[u8]>` block or an mmap borrow. |
| 2 | `FileSystem` `&mut self` reads force one-handle-per-worker + per-thread MFT re-parse; contradicts "lock-free parallel." | **Accepted (central fix).** `FileSystem: Send + Sync`, all reads `&self` over sharded interior mutability. |
| 3 | `SeekAdapter(Mutex<R>)` serializes all workers on one lock. | **Accepted.** `FileSource` uses `pread` / `FileExt::read_at` (no lock); legacy readers use `SeekPoolSource` (cursor pool). |
| 4 | Naive single-mutex LRU block cache = global IO throttle. | **Accepted.** Concurrent sharded / clock-sweep cache (moka-style). |
| 5 | `FsMeta.runs: Vec<ByteRun>` eagerly loaded → OOM on fragmented files. | **Accepted.** Runs removed from `FsMeta`; `extents()` iterator on demand. |
| 6 | Credentials in `PathSpec` + serde is a lose-lose (leak keys or lose them). | **Accepted.** Credentials removed from `PathSpec`; supplied via `CredentialSource` at resolve time. |
| 7 | `comparable` string cache key collides (path bytes contain the delimiter). | **Accepted.** Identity via derived `Hash / Eq` on the enum; human `Display` percent-encodes. |
| 8 | `read_dir -> Vec` OOMs on WinSxS-scale dirs. | **Accepted.** `read_dir -> DirStream` streaming iterator. |
| 9 | No full-disk-encryption layer (BitLocker / LUKS / FileVault). | **Accepted.** New `EncryptionLayer` between volume and FS. |
| 10 | Silent degrade-to-`RawStream` on a prober-Yes-then-fail hides a populated partition. | **Accepted.** `Yes` / `Maybe`-then-fail ⇒ hard `Decode` error; `RawStream` only when NO prober matched, typed `Unknown` + bytes. |
| 11 | Missing NTFS 100 ns (`WinFileTime`) resolution → tamper signal lost. | **Accepted.** Added `TimeResolution::WinFileTime`. |
| 12 | No hardlink enumeration despite `nlink`. | **Accepted.** `FileSystem::hardlinks(ino)` added. |
| 13 | Deterministic first-match on a `Yes` / `Yes` tie silently picks wrong FS. | **Accepted with nuance.** Hard `VfsError::Ambiguous` by default; opt-in `auto_pick` for batch, always with a finding. |
| 14 | Shims-in-`disk-forensic` = god-crate + circular test dep (fig leaf). | **Accepted.** Registry / engine split into `forensic-vfs-engine`; `disk-forensic` thin CLI; readers unit-test against the leaf alone. |

**Biggest risk escalated:** conflation of thread-concurrency with data-mutability (the `&mut self` + `Mutex` serialization). Resolved by the `&self`-all-the-way-down model + positioned OS reads. Residual risk: making each FS reader cheaply `Sync`.

### Round 2 — Codex (GPT-5), on the round-1-revised design

| # | Critique | Resolution |
|---|---|---|
| 1 | Fixed layer order (`VS → Encryption → FS`) is fiction: whole-disk LUKS precedes partitioning; BitLocker sits inside a partition; APFS-encryption is container/volume metadata. | **Accepted (escalated).** Resolver reframed as a **per-node transform graph** — probe all four kinds at each `DynSource`, follow matches in any order. |
| 2 | `&self` + `Sync` FS lets `DirStream` / `ExtentStream` hold shard guards across `next()`; caller then locks another shard → deadlock. | **Accepted.** Lock-order contract added: streams hold **no lock across `next()`**; documented global lock order. |
| 3 | `Box<dyn Iterator + Send + '_>` borrowing `&self` isn't spawn-friendly and forbids non-Send guards. | **Accepted.** Replaced with **owned `DirStream` / `ExtentStream` / `NodeStream`** holding `Arc<dyn FileSystem>` + a `'static` cursor. |
| 4 | Cache coherence across derived sources (SubRange / decrypted / VSS) undefined; `SourceView` pins blocks invisibly. | **Accepted.** `SourceId` + parent lineage; base-source cache keys; pinned bytes budgeted separately from resident. |
| 5 | `forensic-vfs` depending on `forensicnomicon` makes it a policy crate, leaking report/serde into every reader. | **Accepted.** Core is a **true leaf**; `findings` / `history` are non-default features. |
| 6 | Batteries-included registry vs per-reader `vfs` features → Cargo feature-unification hazard. | **Accepted.** Explicit engine features (`default = ["all-readers"]`, per-reader `reader-*`) + CI matrix. |
| 7 | `Inode{ino,seq}` only fits NTFS; ext / APFS / FAT / ISO need their own identity; snapshot id must be in the address. | **Accepted.** `FileId` enum with FS-specific variants; snapshot ancestor scopes the address domain. |
| 8 | Percent-encoded `Display` underspecified → can't round-trip. | **Accepted.** Two forms: lossless canonical URI (percent-encode `/` and `%` too, round-trip test) + lossy human `Display`. |
| 9 | One header+footer window misses GPT backup, VSS, UDF, damaged media. | **Accepted.** `probe(&dyn ProbeReader, &ProbeBudget)` — bounded random reads at multiple offsets, records ranges touched. |
| 10 | Round-1 missed other unbounded `Vec`s: `deleted` / `unallocated` / `data_streams` / `hardlinks` / `read_link` / `findings` / `fs_info`. | **Accepted.** `deleted` / `unallocated` stream; `read_link` / `hardlinks` take caps; JSON bounded. |
| 11 | Allocation status conflated file-level vs run-level (deleted file, reallocated clusters). | **Accepted.** `RunInfo.alloc` (Allocated / Unallocated / Overwritten / Unknown) separate from `FsMeta.allocated`; TSK name/meta/content split. |
| 12 | Still-real gaps: FAT/exFAT chains, stream-kind taxonomy, timezone/localtime, block-size provenance. | **Partially accepted.** `StreamKind` taxonomy, `TimeZonePolicy`, `SectorSizes` added; FAT chain diagnostics scoped as a deferred `fat` provenance extension. |

**Biggest residual risk escalated:** the resolver was still drawn as a linear stack; real evidence is a graph of competing interpretations, translations, snapshots, and views. **Resolved** by the graph-walk resolver; the remaining risk (graph explosion / mount-time laziness / per-FS `Sync` correctness) is tracked as open work.

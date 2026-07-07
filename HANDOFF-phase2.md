# forensic-vfs — Phase 2 Handoff

*Working handoff for the team lead. Uncommitted by design (transient status, not a published-repo artifact). Current as of 2026-07-07.*

## Executive Summary

`forensic-vfs` 0.1.0 is **published** (the leaf was renamed from `forensic-vfs-core`; that name is intentionally gone from crates.io — do not re-publish or "fix" it). The leaf defines the abstract contracts (`ImageSource`, `FileSystem`, `PathSpec`, `Registry` + probe traits) but has **zero consumers** — nothing implements or calls them yet. Phase 2 wires the first proven pair (ewf + NTFS) onto the contracts.

**Status:** the spike de-risked the trait shape (source side fits trivially; FS side needed `ntfs-core` to grow), and **Step 1 is done** — `ntfs-core` now serves all reads through `&self` with FileId-addressed read primitives, on a local branch, strict TDD, fully green. Steps 2–4 (the actual trait impls + end-to-end proof) remain.

**Decision needed from you:** none blocking — just a go/no-go on continuing to Step 2. All design forks were resolved (below).

---

## Locked decisions (from this session)

1. **Adapters live in each reader crate, feature-gated** (`vfs` feature) — fleet-consistent with how analyzers implement `forensicnomicon::report::Observation`. Readers depend *down* on the published VFS leaf.
2. **Evolve `ntfs-core` to `&self` reads** (interior mutability) rather than a `Mutex`-in-adapter shortcut — so the trait's shared-handle concurrency is honestly satisfied. **Done in Step 1.**
3. **Implement in the canonical post-migration repos** — not the archived `~/src/ewf`.
4. **Dependency name correction:** adapters depend on **`forensic-vfs = "0.1"`**, NOT `forensic-vfs-core` (renamed/removed). Nothing to unwind — Step 1 added no VFS dependency (native return types only).

---

## Confirmed repo layout (all published; adapters depend down on `forensic-vfs 0.1`)

| Piece | Canonical location | Crate / version | crates.io |
|---|---|---|---|
| VFS leaf | `~/src/forensic-vfs` | **`forensic-vfs` 0.1.0** | published (renamed from `forensic-vfs-core`) |
| ewf reader | `~/src/ewf-forensic/core` | **`ewf` 0.4.0** (bare name) | published |
| NTFS reader | `~/src/ntfs-forensic/core` | **`ntfs-core` 0.9.0** | published |

`~/src/ewf` is **archived** ("This repository has moved" → `ewf-forensic`). Do not touch it.

---

## Spike verdict (why Step 1 was necessary)

| Contract | Fit against real readers | Action |
|---|---|---|
| `ImageSource` (`len` + `read_at(&self,…)`) | Fits cleanly — `EwfReader` already exposes `read_at(&self, buf, offset)` + `total_size()`; `SourceCursor` (Read+Seek) composes it into `NtfsFs::open()` | ~10-line delegation (Step 3) |
| `FileSystem` (`&self`, FileId-addressed) | Did NOT fit: `NtfsFs` was `&mut self` and **path**-addressed; trait is `&self` and **FileId**-addressed | Step 1 (done) grew the API |

`read_dir`/`lookup` mapped cleanly; the gaps were concurrency (`&mut self`) and addressing (path vs FileId).

---

## Step 1 — DONE (`ntfs-core` `&self` evolution)

**Branch:** `feat/vfs-self-reads` in `~/src/ntfs-forensic` — 4 signed commits, **not pushed, not merged**, tree clean.

```
09c1d54 feat(fs): GREEN — read_data_by_record + runs_by_record (FileId-addressed)
43238a9 test(fs): RED  — read_data_by_record + runs_by_record
5294ba6 feat(fs): GREEN — NtfsFs interior mutability, all reads via &self
9ce4542 test(fs): RED  — reads through shared &self across threads
```

**Pair 1 — interior mutability.** `NtfsFs<R>` holds `Mutex<R>`; every read method is now `&self` (`read_record`, `directory_entries`, `resolve_path`, `read_file[_capped]`, `read_named_stream`, `read_data_stream`, `gather_records`). N workers share one handle + one parsed MFT. The lock is never held across a call to another reader method (deadlock-safe on the non-reentrant `Mutex`); a poisoned lock recovers the guard instead of panicking (Paranoid Gatekeeper). Non-breaking widening; adds a `Sync` impl.

**Pair 2 — FileId-addressed reads.** `read_file` = `resolve_path` + `read_data_by_record`. New public methods:
- `read_data_by_record(rec, stream, max_bytes) -> Vec<u8>` — default/ADS bytes, capped, follows `$ATTRIBUTE_LIST`, LZNT1-decompresses.
- `runs_by_record(rec, stream) -> Vec<Run>` — reassembled non-resident runlist; empty for a resident stream, `NotFound` when absent (for `FileSystem::extents`).

Return types are **native** (`Vec<u8>`/`Vec<Run>`) so `ntfs-core` stays free of any `forensic-vfs` dependency; type-mapping is the Step-2 adapter's job.

**Verification (all green):** 478 lib + 648 workspace tests (6 env-gated real-image tests ignored); `clippy --workspace --all-targets --all-features -D warnings` exit 0 (verified directly); `fmt --check` clean; `fs.rs` **100% line coverage** (0 unannotated uncovered; the 37 pre-existing uncovered lines elsewhere all carry `// cov:unreachable`, untouched).

**Deliberately NOT built:** `meta_by_record`. `FileSystem::meta` assembles from already-public primitives (`read_record` + `parse_attributes` + `StandardInformation::parse` + `FileName::parse` + `MftRecordHeader`), so a dedicated method is redundant surface — that assembly belongs in the Step-2 adapter where it maps straight to `FsMeta`.

---

## Remaining (Steps 2–4)

**Step 2 — `impl FileSystem for NtfsFs`** behind a `vfs` feature in `ntfs-core` (dep **`forensic-vfs = "0.1"`**). Map native types → `FsMeta`/`RunInfo`/`DirEntry`, `FileId::NtfsRef { entry, seq }`. `read_at`→`read_data_by_record`, `extents`→`runs_by_record`, `read_dir`→`read_record`+`directory_entries`, `meta`→SI/FN assembly. Strict TDD.

**Step 3 — `impl ImageSource for ewf::EwfReader`** behind a `vfs` feature in `ewf-forensic/core` (~10-line delegation; dep `forensic-vfs = "0.1"`). Validate against the real `nps-2010-emails.E01` fixture already in that repo.

**Step 4 — end-to-end proof.** Integration test wiring `EwfReader → dyn ImageSource → SourceCursor → NtfsFs → dyn FileSystem`, reading a known file. Tier-1 target: a real NTFS-in-E01 (Case-001 DC01, env-gated — no small NTFS E01 exists in-repo, so either add one or gate on Case-001).

---

## Separate follow-ups (found, not folded in)

- **4n6mount stale dep:** `ewf = { version = "0.2.3", path = "../ewf/ewf" }` — doubly stale (archived repo + old version). Should become registry `ewf = "0.4"`.
- **Consumer wiring:** once Steps 2–4 land, 4n6mount / disk-forensic / issen dispatch through one `dyn FileSystem` instead of per-format branches (the Phase-6 "issen-collapse" payoff).

## Gotchas observed this session

- **`rtk` misreports git commits** — it printed "1 file changed" for a commit that had actually failed (gitsign OIDC timeout). Always confirm HEAD with a plain `git --no-pager log -1`, not the rtk summary.
- **gitsign OIDC can time out mid-run** — wrap commits in `timeout` and retry; `gitsign credential-cache start` is an invalid subcommand (the daemon binary is `gitsign-credential-cache`), but `git -c gpg.x509.program=gitsign tag/commit -s` still signs.

# forensic-vfs — Product Requirements (reverse-written)

*A specification recovered from the shipped code, not a forward plan. Every coverage
claim in §6 is grounded in a same-session grep of the fleet (2026-07); the trait
signatures in §4 are quoted from `crates/core/src`. Decisions behind the design live
as ADRs under [`docs/decisions/`](decisions/).*

## Executive Summary

forensic-vfs is a set of **four positioned-read contracts** that let any forensic
evidence container, volume system, encryption layer, and filesystem compose into one
read-only virtual filesystem, without any layer knowing the concrete type of the layer
beneath it. A `FileSystem` asks its byte source to `read_at(offset, buf)`; whether that
source is a raw `.dd`, a decompressed E01 chunk, a decrypted BitLocker volume, or a
partition window is invisible to it.

Today the **horizontal layers are strong and the vertical layers are empty**: 5 container
readers and 11 filesystem/archive readers implement their contracts in production; the
`VolumeSystem` (partition) and `CryptoLayer` (encryption) contracts have **zero leaf
implementations** — the reader crates exist (MBR/GPT/APM, BitLocker/LUKS/FileVault/
VeraCrypt) but none are wired to the contract yet. Closing those two layers is the
primary remaining work (§7).

The contracts are deliberately minimal and hard to misuse: read-only, cursorless,
`Send + Sync`, opaque node identity, and gated behind an optional `vfs` cargo feature so
a leaf crate depends on forensic-vfs only when a caller wants VFS composition.

## 1. Problem

Digital-forensic tooling re-implements the same plumbing per format: seek-and-read over a
container, walk a partition table, decrypt a volume, parse a filesystem. Each reader
invents its own I/O shape (`Read + Seek`, a bespoke cursor, a whole-image `&[u8]`), so
they do not compose: mounting NTFS-inside-BitLocker-inside-a-partition-inside-an-E01
means gluing four incompatible APIs by hand, and every glue joint is a place to leak a
cursor, allocate an unbounded buffer, or panic on hostile input.

## 2. Goals

- **One byte-source shape** every layer speaks, so containers, volumes, crypto, and
  filesystems stack by composition, not by bespoke glue.
- **Read-only and concurrency-safe by construction** — a contract that *cannot* mutate
  evidence and *can* be shared across threads without interior locking leaking into the
  API.
- **Misuse-resistant identity** — a filesystem exposes nodes as opaque handles, not
  inode integers a caller can fabricate or a path a caller can traverse out of bounds.
- **Panic-free parsing of hostile input** — every field read from evidence goes through
  bounds-checked helpers; malformed data yields an error or a zero, never a crash.
- **Optional dependency** — a reader crate builds and ships without forensic-vfs; the
  contract impl is behind a `vfs` feature a downstream turns on.

## 3. Non-goals

- **No writing.** The contracts are read-only. Evidence integrity is a structural
  property, not a documented request.
- **No mounting mechanism in the contract crate.** FUSE/inode adaptation lives in a
  separate consumer (`forensic-vfs-mount`); the contract knows nothing about inodes.
- **No format detection in the leaf trait.** Probing is a separate concern
  (`ContainerDecoder`/`VolumeSystemProbe`/`CryptoProbe`/`FileSystemProbe` registry
  traits), so a leaf impl need not carry a sniffer.

## 4. The four contracts (as shipped)

Quoted from `crates/core/src`. All four are `Send + Sync`; all reads take `&self`
(cursorless — the offset is an argument, not hidden state).

**`ImageSource`** — a flat, addressable byte image (`source.rs`):

```rust
pub trait ImageSource: Send + Sync {
    fn len(&self) -> u64;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize>;
    fn extents(&self) -> Extents { /* default: one dense run */ }
    fn view(&self, offset: u64, len: usize) -> Option<SourceView<'_>> { /* default None */ }
    fn source_id(&self) -> SourceId { /* default */ }
}
pub type DynSource = Arc<dyn ImageSource>;
```

**`FileSystem`** — a parsed filesystem over some `ImageSource` (`fs.rs`). Node identity
is the opaque `FileId` enum; a data stream is named by `StreamId` (so NTFS ADS / resource
forks are first-class):

```rust
pub trait FileSystem: Send + Sync {
    fn root(&self) -> FileId;
    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream>;
    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>>;
    fn meta(&self, ino: FileId) -> VfsResult<FsMeta>;
    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize>;
    fn read_link(&self, ino: FileId, cap: usize) -> VfsResult<Vec<u8>>;  // capped: hostile symlink can't over-allocate
    // + forensic surface: data_streams, extents, timestamps (MACB), run maps …
}
```

**`VolumeSystem`** — a partition/volume scheme that opens sub-sources (`volume.rs`):

```rust
pub trait VolumeSystem: Send + Sync {
    fn scheme(&self) -> VolumeScheme;
    fn volumes(&self) -> &[VolumeDesc];
    fn open_volume(&self, index: usize) -> VfsResult<DynSource>;  // -> another ImageSource
    fn findings(&self) -> VfsResult<Vec<forensicnomicon::report::Finding>> { /* default empty */ }
}
```

**`CryptoLayer`** — an encryption layer that opens a decrypted sub-source (`crypto.rs`):

```rust
pub trait CryptoLayer: Send + Sync {
    fn scheme(&self) -> CryptoScheme;
    fn open(&self, creds: &dyn CredentialSource) -> VfsResult<DynSource>;  // -> a decrypted ImageSource
    fn findings(&self) -> VfsResult<Vec<forensicnomicon::report::Finding>> { /* default empty */ }
}
```

**Composition** is by return type: `VolumeSystem::open_volume` and `CryptoLayer::open`
both return `DynSource` (`Arc<dyn ImageSource>`), so the output of one layer is the input
of the next. `SubRange` (`adapters.rs`) is the concrete adapter that windows a parent
`ImageSource` into a partition/volume span — it is a struct that `impl ImageSource`, not a
contract.

## 5. Requirements (why the shape is what it is)

| # | Requirement | Mechanism | ADR |
|---|---|---|---|
| R1 | Reads never mutate evidence | contracts expose no `&mut`/write method | [0001](decisions/0001-positioned-read-contract.md) |
| R2 | Cursorless, shareable across threads | `read_at(&self, offset, …)` + `Send + Sync`; no interior seek state | [0001](decisions/0001-positioned-read-contract.md) |
| R3 | Layers compose without knowing each other's type | `open_*` returns `DynSource`; input of the next layer | [0003](decisions/0003-four-layer-composition.md) |
| R4 | Node identity can't be forged / traversed OOB | opaque `FileId` enum + `StreamId`, not raw inodes/paths | [0002](decisions/0002-opaque-fileid-filesystem.md) |
| R5 | forensic-vfs is an optional dependency | impls gated behind `vfs = ["dep:forensic-vfs"]` | [0004](decisions/0004-vfs-feature-gating.md) |
| R6 | Hostile input never panics | field reads via `safe-read`; capped allocations (`read_link` cap) | [0005](decisions/0005-safe-read-substrate.md) |
| R7 | Forensic knowledge lives in one place | `findings()` returns `forensicnomicon::report::Finding` | [0006](decisions/0006-knowledge-in-forensicnomicon.md) |

## 6. Coverage matrix (verified 2026-07)

Grounded in a fleet-wide grep for `impl (ImageSource|FileSystem|VolumeSystem|CryptoLayer) for`.

**`ImageSource` — 5 production impls:** ewf (E01), qcow2, vmdk, vhdx, dmg.
- Crate exists, **no impl yet:** vhd-forensic, livedisk-forensic, disk-forensic.
- **aff4-forensic is test-only** — forensic-vfs is a dev-dependency; the shipped crate
  carries no production impl.

**`FileSystem` — 11 production impls:** ntfs, fat, ext4, apfs, hfsplus, xfs, iso9660, udf,
zip, ad1, dar.
- Crate exists, **no impl yet:** btrfs-forensic, zfs-forensic, refs-forensic.
- **No crate at all:** exFAT, UFS, legacy (non-plus) HFS.

**`VolumeSystem` — 0 impls.** mbr-partition-forensic, gpt-partition-forensic,
apm-partition-forensic all exist; none implement the contract.

**`CryptoLayer` — 0 impls.** bitlocker-forensic, luks-forensic, filevault-forensic,
veracrypt-forensic all exist; none implement the contract.

## 7. Remaining work (the "finish the vision" gap)

Ranked by leverage — the two empty vertical layers unlock whole classes of evidence:

1. **`VolumeSystem` for MBR/GPT/APM** — currently no partitioned image can be walked
   through the contract; `SubRange` exists to window volumes but nothing produces the
   windows. Highest leverage: every real disk image is partitioned.
2. **`CryptoLayer` for BitLocker/LUKS/FileVault/VeraCrypt** — with §7.1 done, encrypted
   volumes compose in. Depends on `CredentialSource` wiring.
3. **`ImageSource` for vhd, and promote aff4 from test-only to production.**
4. **`FileSystem` for btrfs/zfs/refs** (crates exist) and **exFAT/UFS** (new crates).
5. **Retire the standalone `forensic-vfs-engine`** duplicate in favor of
   `crates/engine` ([0007](decisions/0007-retire-standalone-engine.md)).
6. **Wire `forensic-vfs-mount` into `4n6mount`** — the FileSystem→inode adapter exists
   (tests green); it is not yet the mount path.

Deferred items live in the issue tracker, not here — this section states the *current*
frontier, not a task list.

## 8. Peculiar optimization: block-by-block minimal-temp decode

The positioned-read contract enables a memory property the paper (`paper/`) develops in
full: because a `FileSystem` fetches only the byte ranges it needs (`$MFT` records,
directory runs) via `read_at`, and an E01 `ImageSource` decompresses **only the 32 KiB
chunks those ranges overlap** into a one-chunk scratch page, walking a filesystem over a
compressed image touches ~*K* chunks for *K* scattered records — never the whole inflated
image. The contract is what makes this composable rather than a per-reader special case:
the filesystem asks for offsets, the container decides how little to inflate to serve them.

---

*Related: [`architecture.md`](architecture.md) (the terse contract tour),
[`validation.md`](validation.md) (evidence tiers), and the paper under [`../paper/`](../paper/).*

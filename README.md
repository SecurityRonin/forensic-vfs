# forensic-vfs

[![Crates.io](https://img.shields.io/crates/v/forensic-vfs.svg)](https://crates.io/crates/forensic-vfs)
[![docs.rs](https://img.shields.io/docsrs/forensic-vfs)](https://docs.rs/forensic-vfs)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/forensic-vfs/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/forensic-vfs/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/SecurityRonin/forensic-vfs/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Security audit](https://img.shields.io/badge/security-audit-brightgreen.svg)](https://github.com/SecurityRonin/forensic-vfs/actions/workflows/ci.yml)

**One read-only, positioned-read byte edge — `ImageSource` — that every archive, container, volume, encryption, and filesystem reader in the fleet speaks, so a whole evidence stack (`case.7z → E01 → GPT → BitLocker → NTFS`) composes as a single `Arc<dyn ImageSource>` that N workers read in parallel and no code path can write.**

Building forensic tooling in Rust? `forensic-vfs` is the read-only byte-and-filesystem contract every reader in the fleet plugs into. Write a reader **once** and get parallel reads, recursive container/archive/volume/encryption/filesystem composition, and a serializable evidence locator for free.

```bash
cargo add forensic-vfs
```

## Read any evidence image from every thread at once

```rust
use std::sync::Arc;
use forensic_vfs::{FileSource, ImageSource};

let src: Arc<dyn ImageSource> = Arc::new(FileSource::open("evidence.dd")?);

// read_at(&self) has no cursor and no write method — so one source fans out to
// N worker threads with no lock, and a write is uncompilable, not just discouraged.
let mut buf = [0u8; 4096];
src.read_at(0, &mut buf)?;
# Ok::<(), forensic_vfs::VfsError>(())
```

That is the whole promise in one type: **evidence is parallel-readable and read-only by construction.** Wrap the shipped adapters instead of rolling your own — `FileSource` (positioned OS reads, no `Mutex<File>`), `SubRange` (a byte window that is itself a source), `SourceCursor` (a `Read + Seek` bridge).

## Plug in a new format in 30 seconds

Every container, archive, volume system, encryption layer, or filesystem plugs in through one of five layer-open traits — each a two-step `probe()` (recognize) + `open()` (peel), named for its `open()` method the way Rust's `Read` is named for `read`:

```rust
use std::sync::Arc;
use forensic_vfs::{ContainerOpen, Confidence, SniffWindow, DynSource, VfsResult};

struct MyContainer;

impl ContainerOpen for MyContainer {
    fn probe(&self, window: &SniffWindow) -> Confidence {        // recognize — bounded head, no decode
        if window.starts_with(b"MYFMT") { Confidence::Yes } else { Confidence::No }
    }
    fn open(&self, src: DynSource) -> VfsResult<DynSource> {     // peel one layer — the resolver re-sniffs the result
        Ok(Arc::new(MyDecodedSource::new(src)?))
    }
}
```

Register it in an `Openers` table and the resolver, the engine, and the CLI all dispatch to it automatically. You wrote the format; the composition came for free.

*(New here? The [architecture](docs/architecture.md) explains the layered model; everything below is the tour.)*

## The five layer-open traits

Each peels exactly one layer and hands back a source (or member set) the resolver re-enters:

| Trait | `open()` yields | Formats |
|---|---|---|
| `ContainerOpen` | `DynSource` | E01/EWF, VMDK, VHD, VHDX, QCOW2, DMG, AFF4, raw |
| `ArchiveOpen` | `ArchiveContents` | gz, bz2, tar, zip, clbx, 7z, AD1, DAR |
| `VolumeSystemOpen` | `Box<dyn VolumeSystem>` | MBR, GPT, APM |
| `EncryptionOpen` | `Box<dyn EncryptionLayer>` | BitLocker, LUKS, FileVault, VeraCrypt |
| `FileSystemOpen` | `DynFs` | NTFS, FAT, ext4, XFS, btrfs, APFS, HFS+, UFS, ISO9660, UDF |

Archives are a first-class layer with their own trait ([ADR 0008](docs/decisions/0008-archives-as-probes.md)); `ArchiveOpen::open` returns either a decoded single stream or a member list:

```rust
enum ArchiveContents {
    Stream(DynSource),     // 1→1: a bare gz/bz2 wrapper — the decoded source re-enters resolution
    Members(Vec<Member>),  // 1→N: tar/zip/7z — each member re-enters resolution
}
```

## The reader fleet

Every reader below speaks the `forensic-vfs` contract; the resolver composes them into one `Arc<dyn ImageSource>`. Status legend: **✓ wired** — implements the contract in `src/vfs.rs` today · **via disk-forensic** — reaches the contract through `disk_forensic::container::open`, not a direct impl · **not wired yet** — crate exists, no contract impl · **→ ArchiveOpen at 0.4** — implements `FileSystem` today, reclassifies to `ArchiveOpen` at the 0.4 cut. Crates without a link are in-workspace or not yet on GitHub (marked *local*).

**Knowledge / contract** — the leaf types every reader depends on.

| Crate | Role |
|---|---|
| [forensicnomicon](https://github.com/SecurityRonin/forensicnomicon) | format magics + the `report` finding model |
| [safe-read](https://github.com/SecurityRonin/safe-read) | bounded, panic-free positioned reads |
| [state-history-forensic](https://github.com/SecurityRonin/state-history-forensic) | temporal identity `[H]` |
| **forensic-vfs** | this crate — `ImageSource` + the five `*Open` contracts |
| forensic-vfs-resolver *(local)* | the `SourceOpen` orchestrator (recursive descent) |
| [forensic-vfs-engine](https://github.com/SecurityRonin/forensic-vfs-engine) | `default_openers()` wiring the concrete readers |

**1 · Archive** (`ArchiveOpen`)

| Reader | Formats | Status |
|---|---|---|
| archive-forensic *(local)* | gz, bz2, tar, zip, clbx, 7z | wired via archive-core |
| [ad1-forensic](https://github.com/SecurityRonin/ad1-forensic) | AD1 | → ArchiveOpen at 0.4 |
| [dar-forensic](https://github.com/SecurityRonin/dar-forensic) | DAR | → ArchiveOpen at 0.4 |
| [zip-forensic](https://github.com/SecurityRonin/zip-forensic) | ZIP | → ArchiveOpen at 0.4 |

**2 · Container** (`ContainerOpen` → `ImageSource`)

| Reader | Format | Status |
|---|---|---|
| [ewf-forensic](https://github.com/SecurityRonin/ewf-forensic) | E01 / EWF | ✓ wired |
| [qcow2-forensic](https://github.com/SecurityRonin/qcow2-forensic) | QCOW2 | ✓ wired |
| [vhdx-forensic](https://github.com/SecurityRonin/vhdx-forensic) | VHDX | ✓ wired |
| [vhd-forensic](https://github.com/SecurityRonin/vhd-forensic) | VHD | ✓ wired |
| [aff4-forensic](https://github.com/SecurityRonin/aff4-forensic) | AFF4 | ✓ wired |
| [vmdk-forensic](https://github.com/SecurityRonin/vmdk-forensic) | VMDK | via disk-forensic |
| [dmg-forensic](https://github.com/SecurityRonin/dmg-forensic) | DMG | via disk-forensic |

**3 · Volume / partition** (`VolumeSystemOpen`)

| Reader | Scheme | Status |
|---|---|---|
| [mbr-partition-forensic](https://github.com/SecurityRonin/mbr-partition-forensic) | MBR | ✓ wired |
| [gpt-partition-forensic](https://github.com/SecurityRonin/gpt-partition-forensic) | GPT | ✓ wired |
| [apm-partition-forensic](https://github.com/SecurityRonin/apm-partition-forensic) | APM | ✓ wired |

**4 · Encryption** (`EncryptionOpen`)

| Reader | Scheme | Status |
|---|---|---|
| [bitlocker-forensic](https://github.com/SecurityRonin/bitlocker-forensic) | BitLocker | not wired yet |
| [luks-forensic](https://github.com/SecurityRonin/luks-forensic) | LUKS | not wired yet |
| [filevault-forensic](https://github.com/SecurityRonin/filevault-forensic) | FileVault | not wired yet |
| [veracrypt-forensic](https://github.com/SecurityRonin/veracrypt-forensic) | VeraCrypt | not wired yet |

**5 · Filesystem** (`FileSystemOpen` → `FileSystem`)

| Reader | Filesystem | Status |
|---|---|---|
| [ntfs-forensic](https://github.com/SecurityRonin/ntfs-forensic) | NTFS | ✓ wired |
| [fat-forensic](https://github.com/SecurityRonin/fat-forensic) | FAT / exFAT | ✓ wired |
| [ext4fs-forensic](https://github.com/SecurityRonin/ext4fs-forensic) | ext4 | ✓ wired |
| [xfs-forensic](https://github.com/SecurityRonin/xfs-forensic) | XFS | ✓ wired |
| [btrfs-forensic](https://github.com/SecurityRonin/btrfs-forensic) | btrfs | ✓ wired |
| [apfs-forensic](https://github.com/SecurityRonin/apfs-forensic) | APFS | ✓ wired |
| [hfsplus-forensic](https://github.com/SecurityRonin/hfsplus-forensic) | HFS+ | ✓ wired |
| [ufs-forensic](https://github.com/SecurityRonin/ufs-forensic) | UFS | ✓ wired |
| [iso9660-forensic](https://github.com/SecurityRonin/iso9660-forensic) | ISO9660 | ✓ wired |
| [udf-forensic](https://github.com/SecurityRonin/udf-forensic) | UDF | ✓ wired |

**Consumers** — depend on the abstraction, never on a per-format reader.

| Crate | Role |
|---|---|
| [disk-forensic](https://github.com/SecurityRonin/disk-forensic) | open-any-image + partition / ISO analysis |
| [4n6mount](https://github.com/SecurityRonin/4n6mount) | FUSE mount of any composed stack |
| [issen](https://github.com/SecurityRonin/issen) | fleet orchestrator |

## One `SourceOpen` peels the whole stack

The five `*Open` traits each peel *one* layer. The single `SourceOpen` orchestrator (in the sibling `forensic-vfs-resolver` crate) peels *all* of them by delegating: at each node it probes the five layer-opens, follows the match, and re-enters on the result until a filesystem mounts.

```rust
use forensic_vfs_resolver::SourceOpen;

let resolved = openers.open(source)?;   // recursive descent — container ∘ archive ∘ volume ∘ encryption ∘ filesystem
```

Because `open()` re-enters per layer and per member, the *depth is discovered by content*, not fixed by a lane. Same algorithm, two very different outcomes:

```text
case.7z of loose documents
  └─ ArchiveOpen → Members → each member is a leaf file            (shallow)

case.7z holding case.E01
  └─ ArchiveOpen → Members → member re-enters SourceOpen:
       ContainerOpen(EWF) → VolumeSystemOpen(GPT)
         → EncryptionOpen(BitLocker) → FileSystemOpen(NTFS) → file tree   (deep)
```

Real evidence nests in any order — `raw → LUKS → LVM → ext4` (encryption before volume), `E01 → APFS-container(encrypted) → APFS` (encryption is container metadata) — so `SourceOpen` is a per-node graph, not a fixed stack. The `PathSpec` records the full path taken. Composition is exactly **five transform kinds** — container · archive · volume · encryption · filesystem ([ADR 0003](docs/decisions/0003-four-layer-composition.md)).

## Address any node with a `PathSpec`

A `PathSpec` is the recursive, self-describing locator a finding cites and a session re-opens. It round-trips byte-for-byte through a canonical URI (a fuzz-enforced invariant):

```rust
use forensic_vfs::PathSpec;

let spec = PathSpec::from_uri(
    "fvfs:os:%2Fevidence%2FDC01.E01|container:ewf|volume:gpt,1|fs:ntfs,p/Windows/System32/config/SYSTEM",
)?;
assert_eq!(PathSpec::from_uri(&spec.to_uri())?, spec); // lossless
# Ok::<(), forensic_vfs::VfsError>(())
```

Every byte outside `[A-Za-z0-9._-]` is percent-encoded, so a Windows path containing `/` or a non-UTF-8 filename survives intact. Credentials never live in the address — they are supplied out-of-band through a `CredentialSource` at open time.

## Crate topology

| Crate | Role |
|---|---|
| **`forensic-vfs`** (0.4) | the contract leaf — `ImageSource`, the five `*Open` traits, `Openers`, `PathSpec`, `FsMeta`, `FsKind` |
| **`forensic-vfs-resolver`** (0.1) | the `SourceOpen` orchestrator — `impl SourceOpen for Openers`, recursive descent, `walk`, `snapshot_view` |
| **`forensic-vfs-engine`** ([repo](https://github.com/SecurityRonin/forensic-vfs-engine)) | `default_openers()` wiring the ~17 concrete readers + `Vfs::open(path)` host bootstrap |

A consumer depends on the abstraction (leaf + resolver), never on a per-format reader. Adding a new format benefits every consumer at once.

## Trust but verify

- **Fuzzed.** The `PathSpec` URI parser and the bounded readers are fuzzed — 15.7M + 20.2M executions with no panic, the round-trip invariant holding throughout.
- **Panic-free by lint.** `unsafe_code = forbid`; `unwrap_used`/`expect_used` denied; every offset/length read goes through bounded readers that return 0, never panic, out of range.
- **100% line coverage**, with object-safety of every trait proven by a reader double driven through `Arc<dyn Trait>`.

## Where this fits

The horizontal layers are strong; the two vertical layers are the frontier — container and filesystem/archive readers implement their contracts in production, while the volume and encryption readers (MBR/GPT/APM, BitLocker/LUKS/FileVault) exist but are not yet wired to `VolumeSystemOpen`/`EncryptionOpen`. Full architecture, the exact coverage matrix, and the design decisions:

- [`docs/architecture.md`](docs/architecture.md) — the layered model, the resolver graph, and the crate topology
- [`docs/PRD.md`](docs/PRD.md) — reverse-written requirements + coverage matrix + remaining work
- [`docs/decisions/`](docs/decisions/) — ADRs (positioned-read, five-layer composition, first-class archives, …)
- [`paper/`](paper/) — the academic write-up (universal reader + safe-read + block-by-block E01/MFT decode)

---

[Privacy Policy](https://securityronin.github.io/forensic-vfs/privacy/) · [Terms of Service](https://securityronin.github.io/forensic-vfs/terms/) · © 2026 Security Ronin Ltd

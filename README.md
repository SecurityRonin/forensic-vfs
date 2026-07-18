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

**One read-only, positioned-read byte edge — `ImageSource` — that every disk, container, archive, and filesystem reader in the fleet speaks, so a whole evidence stack (`E01 → GPT → BitLocker → NTFS`) composes as a single `Arc<dyn ImageSource>` that N workers read in parallel and no code path can write.**

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
| `ContainerOpen` | `DynSource` | E01/EWF, VMDK, VHDX, QCOW2, DMG, AFF4 |
| `ArchiveOpen` | `ArchiveContents` | gz, bz2, tar, zip, 7z |
| `VolumeSystemOpen` | `Box<dyn VolumeSystem>` | MBR, GPT, APM, VSS |
| `EncryptionOpen` | `Box<dyn EncryptionLayer>` | BitLocker, LUKS, FileVault |
| `FileSystemOpen` | `DynFs` | NTFS, ext4, APFS, HFS+, FAT, ISO |

Archives are a first-class layer with their own trait ([ADR 0008](docs/decisions/0008-archives-as-probes.md)); `ArchiveOpen::open` returns either a decoded single stream or a member list:

```rust
enum ArchiveContents {
    Stream(DynSource),     // 1→1: a bare gz/bz2 wrapper — the decoded source re-enters resolution
    Members(Vec<Member>),  // 1→N: tar/zip/7z — each member re-enters resolution
}
```

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

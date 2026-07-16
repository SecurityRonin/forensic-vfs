# forensic-vfs

[![Crates.io](https://img.shields.io/crates/v/forensic-vfs.svg)](https://crates.io/crates/forensic-vfs)
[![docs.rs](https://img.shields.io/docsrs/forensic-vfs)](https://docs.rs/forensic-vfs)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/forensic-vfs/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/forensic-vfs/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/SecurityRonin/forensic-vfs/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

**One read-only, positioned-read byte edge — `ImageSource` — that every disk, container, and filesystem reader in the fleet speaks, so a whole evidence stack (`E01 → GPT → BitLocker → NTFS`) composes as a single `Arc<dyn ImageSource>` that N workers read in parallel and no code path can write.**

`forensic-vfs` is the KNOWLEDGE-leaf contract crate of the universal forensic VFS. It defines the layered model — byte source, volume system, crypto layer, filesystem, and the recursive `PathSpec` locator — plus the generic layer resolver (`Registry::resolve`, `walk`), and nothing that touches a concrete format: no parsing, no reader dependencies. Readers implement these traits and register in a `Registry`; the fleet orchestration layer wires the concrete readers and the `disk4n6` CLI over them.

## The one decision that shapes everything

```rust
pub trait ImageSource: Send + Sync {
    fn len(&self) -> u64;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError>;
    // no seek cursor, and no write method — anywhere
}
```

Positioned reads (`read_at`) carry no cursor, so one source is shared across threads by `&self` — a `Read + Seek` cursor's `&mut self` cannot. And there is no write method to misuse: **evidence is read-only in the type system, not by convention.** A write is uncompilable.

## Implement a reader in 30 seconds

```rust
use forensic_vfs::{ImageSource, VfsResult};

struct RawFile(std::fs::File, u64);

impl ImageSource for RawFile {
    fn len(&self) -> u64 { self.1 }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        use std::os::unix::fs::FileExt;
        Ok(self.0.read_at(buf, offset)?)   // positioned, lock-free, parallel-safe
    }
}
```

`forensic-vfs` ships `FileSource` (this, cross-platform), `SubRange` (a byte window that is itself an `ImageSource`), and `SourceCursor` (a `Read + Seek` bridge for legacy call sites) — so most readers wrap an existing source rather than write one.

## Address any node with a `PathSpec`

A `PathSpec` is the recursive, self-describing locator a finding cites and a session re-opens. It round-trips byte-for-byte through a canonical URI:

```rust
use forensic_vfs::PathSpec;

let spec = PathSpec::from_uri(
    "fvfs:os:%2Fevidence%2FDC01.E01|container:ewf|volume:gpt,1|fs:ntfs,p/Windows/System32/config/SYSTEM",
)?;
assert_eq!(PathSpec::from_uri(&spec.to_uri())?, spec); // lossless
# Ok::<(), forensic_vfs::VfsError>(())
```

Every byte outside `[A-Za-z0-9._-]` is percent-encoded, so a Windows path containing `/` or a non-UTF-8 filename survives intact. Credentials never live in the address — they are supplied out-of-band at resolve time.

## Trust but verify

- **Panic-free.** `unsafe_code = forbid`; no `unwrap`/`expect`/`panic!` in production; every offset/length read goes through bounded readers that return 0, never panic, out of range.
- **Fuzzed.** The `PathSpec` URI parser and the bounded readers are fuzzed — 15.7M + 20.2M executions with no panic, the round-trip invariant holding throughout.
- **100% line coverage**, object-safety of every trait proven by a reader double driven through `Arc<dyn Trait>`.

## Where this fits

`forensic-vfs` is the contract crate plus the generic resolver. Readers implement
its traits behind a `vfs` feature; the fleet orchestration layer registers the
concrete readers and drives `Registry::resolve` over them. Verified coverage (2026-07):

| Layer | Contract | Production impls |
|---|---|---|
| Containers | `ImageSource` | ewf (E01), qcow2, vmdk, vhdx, dmg — **5** |
| Filesystems / archives | `FileSystem` | ntfs, fat, ext4, apfs, hfsplus, xfs, iso9660, udf, zip, ad1, dar — **11** |
| Volumes | `VolumeSystem` | *none yet* (mbr/gpt/apm crates exist, unwired) |
| Crypto | `CryptoLayer` | *none yet* (bitlocker/luks/filevault/veracrypt exist, unwired) |

The horizontal layers are strong; the two vertical layers are the frontier. Full
architecture, the exact coverage matrix, and the design decisions:

- [`docs/PRD.md`](docs/PRD.md) — reverse-written requirements + coverage matrix + remaining work
- [`docs/decisions/`](docs/decisions/) — ADRs (positioned-read, feature-gating, composition, …)
- [`paper/`](paper/) — the academic write-up (universal reader + safe-read + block-by-block E01/MFT decode)

---

[Privacy Policy](https://securityronin.github.io/forensic-vfs/privacy/) · [Terms of Service](https://securityronin.github.io/forensic-vfs/terms/) · © 2026 Security Ronin Ltd

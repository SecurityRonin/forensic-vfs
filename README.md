# forensic-vfs

[![Crates.io](https://img.shields.io/crates/v/forensic-vfs-core.svg)](https://crates.io/crates/forensic-vfs-core)
[![docs.rs](https://img.shields.io/docsrs/forensic-vfs-core)](https://docs.rs/forensic-vfs-core)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/forensic-vfs/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/forensic-vfs/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/SecurityRonin/forensic-vfs/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

**One read-only, positioned-read byte edge — `ImageSource` — that every disk, container, and filesystem reader in the fleet speaks, so a whole evidence stack (`E01 → GPT → BitLocker → NTFS`) composes as a single `Arc<dyn ImageSource>` that N workers read in parallel and no code path can write.**

`forensic-vfs-core` is the KNOWLEDGE-leaf contract crate of the universal forensic VFS. It defines the layered model — byte source, volume system, crypto layer, filesystem, and the recursive `PathSpec` locator — and nothing else: no format parsing, no reader dependencies. Readers implement these traits; the engine (`forensic-vfs-engine`) and the `disk4n6` CLI compose them.

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
use forensic_vfs_core::{ImageSource, VfsResult};

struct RawFile(std::fs::File, u64);

impl ImageSource for RawFile {
    fn len(&self) -> u64 { self.1 }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        use std::os::unix::fs::FileExt;
        Ok(self.0.read_at(buf, offset)?)   // positioned, lock-free, parallel-safe
    }
}
```

`forensic-vfs-core` ships `FileSource` (this, cross-platform), `SubRange` (a byte window that is itself an `ImageSource`), and `SourceCursor` (a `Read + Seek` bridge for legacy call sites) — so most readers wrap an existing source rather than write one.

## Address any node with a `PathSpec`

A `PathSpec` is the recursive, self-describing locator a finding cites and a session re-opens. It round-trips byte-for-byte through a canonical URI:

```rust
use forensic_vfs_core::PathSpec;

let spec = PathSpec::from_uri(
    "fvfs:os:%2Fevidence%2FDC01.E01|container:ewf|volume:gpt,1|fs:ntfs,p/Windows/System32/config/SYSTEM",
)?;
assert_eq!(PathSpec::from_uri(&spec.to_uri())?, spec); // lossless
# Ok::<(), forensic_vfs_core::VfsError>(())
```

Every byte outside `[A-Za-z0-9._-]` is percent-encoded, so a Windows path containing `/` or a non-UTF-8 filename survives intact. Credentials never live in the address — they are supplied out-of-band at resolve time.

## Trust but verify

- **Panic-free.** `unsafe_code = forbid`; no `unwrap`/`expect`/`panic!` in production; every offset/length read goes through bounded readers that return 0, never panic, out of range.
- **Fuzzed.** The `PathSpec` URI parser and the bounded readers are fuzzed — 15.7M + 20.2M executions with no panic, the round-trip invariant holding throughout.
- **100% line coverage**, object-safety of every trait proven by a reader double driven through `Arc<dyn Trait>`.

## Where this fits

`forensic-vfs-core` realizes Phase 1 of the universal forensic VFS. The layers above it are in development:

| Crate | Role | Status |
|---|---|---|
| **`forensic-vfs-core`** | byte source, volume/crypto/filesystem traits, `PathSpec` | this crate |
| `forensic-vfs-engine` | registry + graph resolver over every reader | planned |
| `disk-forensic` / `disk4n6` | thin CLI over the engine | evolving |

See the design in [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic/blob/main/docs/design/2026-07-06-universal-forensic-vfs.md).

---

[Privacy Policy](https://securityronin.github.io/forensic-vfs/privacy/) · [Terms of Service](https://securityronin.github.io/forensic-vfs/terms/) · © 2026 Security Ronin Ltd

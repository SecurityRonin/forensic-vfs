//! # forensic-vfs
//!
//! The read-only forensic virtual-filesystem **contracts** — the KNOWLEDGE leaf
//! every disk/container/filesystem reader in the fleet implements. It defines the
//! layered model and nothing else: no format parsing, no I/O beyond the thin
//! [`adapters`] that wrap an OS file, no reader dependencies.
//!
//! ## The layered model
//!
//! ```text
//! PathSpec (recursive locator)
//!    │ resolves (a per-node transform graph, in the engine)
//!    ▼
//! ImageSource  ── the universal edge: read-only positioned bytes ──────────┐
//!    ├── ContainerDecoder : E01/VMDK/VHDX/… → ImageSource                   │  any of these
//!    ├── VolumeSystem     : MBR/GPT/VSS/…    → ImageSource                   │  transforms may
//!    ├── CryptoLayer      : BitLocker/LUKS/… → ImageSource                   │  apply, in any
//!    └── FileSystem       : NTFS/ext4/APFS/… → FsNode tree                   ┘  order, per node
//! ```
//!
//! ## Load-bearing decisions
//!
//! - **[`ImageSource`] is a positioned-read `&self` byte source with no write
//!   method.** Parallel-safe by construction (workers share one `Arc<dyn
//!   ImageSource>`), and read-only in the type system — a write is uncompilable.
//! - **[`FileSystem`] reads are `&self`** over interior mutability, so one mounted
//!   handle serves N workers; bulk enumerations are owned `Send` streams.
//! - **[`PathSpec`] identity is the structured enum**, with a lossless canonical
//!   URI ([`uri`]) for reports and a lossy human `Display`.
//! - **True leaf.** Base deps are `thiserror` (+ optional `serde`); the
//!   [`forensicnomicon`](https://docs.rs/forensicnomicon) findings bridge and the
//!   history bridge are non-default features, so a bare reader inherits neither.
//!
//! Panic-free (Paranoid Gatekeeper): `unsafe_code = forbid`, no
//! `unwrap`/`expect`/`panic!` in production, bounded readers over every
//! attacker-controllable length/offset.

// Tests may unwrap/expect freely; production code may not.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod adapters;
pub mod crypto;
pub mod error;
pub mod fs;
pub mod pathspec;
pub mod read;
pub mod registry;
pub mod source;
pub mod uri;
pub mod volume;

pub use crypto::{Credential, CredentialSource, CryptoLayer, CryptoScheme};
pub use error::{SmallHex, VfsError, VfsResult};
pub use fs::{
    Allocation, ByteRun, DirEntry, DirStream, DynFs, ExtentStream, FileId, FileSystem, FsKind,
    FsMeta, HardLink, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc, RunFlags, RunInfo,
    SectorSizes, StreamId, StreamInfo, StreamKind, TimeResolution, TimeSource, TimeStamp,
    TimeZonePolicy,
};
pub use pathspec::{Guid, Layer, NodeAddr, PathSpec, SnapshotRef};
pub use registry::{
    Confidence, ContainerDecoder, ContainerFormat, CryptoProbe, FileSystemProbe, Registry,
    SniffWindow, VolumeSystemProbe,
};
pub use source::{read_exact_at, DynSource, Extent, Extents, ImageSource, SourceId, SourceView};
pub use volume::{VolumeDesc, VolumeKind, VolumeScheme, VolumeSystem};

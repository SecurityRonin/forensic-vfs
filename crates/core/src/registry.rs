//! The plugin contracts and the compiled-in dispatch [`Registry`].
//!
//! A reader implements one of the four probe traits; the engine
//! (`forensic-vfs-engine`) fills a [`Registry`] with every reader and drives the
//! resolver. The table is explicit and greppable — not a link-time `inventory`
//! registration — so the dependency graph stays auditable and detection order is
//! deterministic.

use crate::encryption::EncryptionLayer;
use crate::error::VfsResult;
use crate::fs::{DynFs, FsKind};
use crate::source::DynSource;
use crate::volume::{VolumeScheme, VolumeSystem};

/// The outer container/image format.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainerFormat {
    Ewf,
    Vmdk,
    Vhdx,
    Vhd,
    Qcow2,
    Dmg,
    Aff4,
    Ad1,
    Dar,
    /// A flat raw/dd image (no wrapper).
    Raw,
    /// Sniff the format at resolve time.
    Auto,
}

/// A prober's verdict. `Yes` carries *how* it matched, for the ambiguity report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    No,
    Maybe,
    Yes { how: &'static str },
}

impl Confidence {
    /// True for `Yes`/`Maybe` — worth attempting `open`.
    #[must_use]
    pub fn is_candidate(self) -> bool {
        !matches!(self, Confidence::No)
    }

    /// True only for a definite `Yes`.
    #[must_use]
    pub fn is_yes(self) -> bool {
        matches!(self, Confidence::Yes { .. })
    }
}

/// A bounded window of bytes handed to a prober. Holds a prefix of the source
/// (the *head*) plus the absolute base offset that prefix starts at, so a prober
/// reads magic without an unbounded scan and without touching the source
/// directly. It also carries the source's `total_len` and a *tail* window (the
/// last N bytes), so a prober can match a trailer signature — e.g. the DMG
/// `koly` footer at `total_len - 512` — that the head window never reaches.
pub struct SniffWindow<'a> {
    base: u64,
    bytes: &'a [u8],
    total_len: u64,
    tail: &'a [u8],
}

impl<'a> SniffWindow<'a> {
    /// A head-only window of `bytes` that begins at absolute `base` in the
    /// source. `total_len` is inferred as `base + bytes.len()` and the tail is
    /// empty — existing head-magic probers are unaffected.
    #[must_use]
    pub fn new(base: u64, bytes: &'a [u8]) -> Self {
        Self {
            base,
            bytes,
            total_len: base.saturating_add(bytes.len() as u64),
            tail: &[],
        }
    }

    /// A window carrying both a head (`bytes` at `base`) and a `tail` (the last
    /// bytes of the source), plus the source's `total_len`. `tail` must end at
    /// `total_len` for the from-end probes to be correct.
    #[must_use]
    pub fn with_tail(base: u64, bytes: &'a [u8], total_len: u64, tail: &'a [u8]) -> Self {
        Self {
            base,
            bytes,
            total_len,
            tail,
        }
    }

    /// The absolute offset the window starts at.
    #[must_use]
    pub fn base(&self) -> u64 {
        self.base
    }

    /// The window (head) bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// The total length of the source this window was sniffed from.
    #[must_use]
    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    /// The `n` bytes at window-relative `off`, or `None` if out of range. Never
    /// panics — the panic-free way to test a magic.
    #[must_use]
    pub fn at(&self, off: usize, n: usize) -> Option<&[u8]> {
        let end = off.checked_add(n)?;
        self.bytes.get(off..end)
    }

    /// True when the window has `magic` at window-relative `off`.
    #[must_use]
    pub fn has_magic(&self, off: usize, magic: &[u8]) -> bool {
        self.at(off, magic.len()) == Some(magic)
    }

    /// The `n` bytes of the tail beginning `from_end` bytes before the source's
    /// end, or `None` when the tail is too short. Never panics.
    #[must_use]
    pub fn tail_at(&self, from_end: usize, n: usize) -> Option<&[u8]> {
        let start = self.tail.len().checked_sub(from_end)?;
        let end = start.checked_add(n)?;
        self.tail.get(start..end)
    }

    /// True when the tail carries `magic` starting `from_end` bytes before the
    /// source's end (e.g. `has_magic_from_end(512, b"koly")` for a DMG footer).
    /// False if the tail is too short — the panic-free trailer probe.
    #[must_use]
    pub fn has_magic_from_end(&self, from_end: usize, magic: &[u8]) -> bool {
        self.tail_at(from_end, magic.len()) == Some(magic)
    }
}

/// Decodes an outer container to a raw byte stream.
pub trait ContainerDecoder: Send + Sync {
    fn format(&self) -> ContainerFormat;
    fn probe(&self, w: &SniffWindow) -> Confidence;
    fn open(&self, src: DynSource) -> VfsResult<DynSource>;
}

/// Recognizes and opens a partitioning/volume scheme.
pub trait VolumeSystemProbe: Send + Sync {
    fn scheme(&self) -> VolumeScheme;
    fn probe(&self, w: &SniffWindow) -> Confidence;
    fn open(&self, src: DynSource) -> VfsResult<Box<dyn VolumeSystem>>;
}

/// Recognizes and opens a full-disk-encryption layer.
pub trait EncryptionProbe: Send + Sync {
    fn scheme(&self) -> crate::encryption::EncryptionScheme;
    fn probe(&self, w: &SniffWindow) -> Confidence;
    fn open(&self, src: DynSource) -> VfsResult<Box<dyn EncryptionLayer>>;
}

/// Recognizes and mounts a filesystem.
pub trait FileSystemProbe: Send + Sync {
    fn kind(&self) -> FsKind;
    fn probe(&self, w: &SniffWindow) -> Confidence;
    fn open(&self, src: DynSource) -> VfsResult<DynFs>;
}

/// The compiled-in dispatch table. Populated by the engine's `default_registry()`;
/// held here so any tool/test can build one without a circular dep through a
/// binary crate.
#[derive(Default)]
pub struct Registry {
    containers: Vec<Box<dyn ContainerDecoder>>,
    volume_systems: Vec<Box<dyn VolumeSystemProbe>>,
    encryption: Vec<Box<dyn EncryptionProbe>>,
    filesystems: Vec<Box<dyn FileSystemProbe>>,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a container decoder (builder style).
    #[must_use]
    pub fn container(mut self, d: impl ContainerDecoder + 'static) -> Self {
        self.containers.push(Box::new(d));
        self
    }

    /// Register a volume-system prober.
    #[must_use]
    pub fn volume_system(mut self, p: impl VolumeSystemProbe + 'static) -> Self {
        self.volume_systems.push(Box::new(p));
        self
    }

    /// Register a encryption prober.
    #[must_use]
    pub fn encryption(mut self, p: impl EncryptionProbe + 'static) -> Self {
        self.encryption.push(Box::new(p));
        self
    }

    /// Register a filesystem prober.
    #[must_use]
    pub fn filesystem(mut self, p: impl FileSystemProbe + 'static) -> Self {
        self.filesystems.push(Box::new(p));
        self
    }

    /// The registered container decoders, in registration order.
    #[must_use]
    pub fn containers(&self) -> &[Box<dyn ContainerDecoder>] {
        &self.containers
    }
    /// The registered volume-system probers.
    #[must_use]
    pub fn volume_systems(&self) -> &[Box<dyn VolumeSystemProbe>] {
        &self.volume_systems
    }
    /// The registered encryption probers.
    #[must_use]
    pub fn encryption_layers(&self) -> &[Box<dyn EncryptionProbe>] {
        &self.encryption
    }
    /// The registered filesystem probers.
    #[must_use]
    pub fn filesystems(&self) -> &[Box<dyn FileSystemProbe>] {
        &self.filesystems
    }
}

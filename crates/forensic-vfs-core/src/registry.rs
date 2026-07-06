//! The plugin contracts and the compiled-in dispatch [`Registry`].
//!
//! A reader implements one of the four probe traits; the engine
//! (`forensic-vfs-engine`) fills a [`Registry`] with every reader and drives the
//! resolver. The table is explicit and greppable — not a link-time `inventory`
//! registration — so the dependency graph stays auditable and detection order is
//! deterministic.

use crate::crypto::CryptoLayer;
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
/// plus the absolute base offset that prefix starts at, so a prober reads magic
/// without an unbounded scan and without touching the source directly.
pub struct SniffWindow<'a> {
    base: u64,
    bytes: &'a [u8],
}

impl<'a> SniffWindow<'a> {
    /// A window of `bytes` that begins at absolute `base` in the source.
    #[must_use]
    pub fn new(base: u64, bytes: &'a [u8]) -> Self {
        Self { base, bytes }
    }

    /// The absolute offset the window starts at.
    #[must_use]
    pub fn base(&self) -> u64 {
        self.base
    }

    /// The window bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes
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
pub trait CryptoProbe: Send + Sync {
    fn scheme(&self) -> crate::crypto::CryptoScheme;
    fn probe(&self, w: &SniffWindow) -> Confidence;
    fn open(&self, src: DynSource) -> VfsResult<Box<dyn CryptoLayer>>;
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
    crypto: Vec<Box<dyn CryptoProbe>>,
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

    /// Register a crypto prober.
    #[must_use]
    pub fn crypto(mut self, p: impl CryptoProbe + 'static) -> Self {
        self.crypto.push(Box::new(p));
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
    /// The registered crypto probers.
    #[must_use]
    pub fn crypto_layers(&self) -> &[Box<dyn CryptoProbe>] {
        &self.crypto
    }
    /// The registered filesystem probers.
    #[must_use]
    pub fn filesystems(&self) -> &[Box<dyn FileSystemProbe>] {
        &self.filesystems
    }
}

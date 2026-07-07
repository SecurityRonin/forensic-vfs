//! [`PathSpec`] — the recursive, self-describing locator.
//!
//! A chain of [`Layer`] nodes, each naming one layer, its location within that
//! layer, and its parent. It is the cache key, the reproducibility record, and
//! what a report cites. It carries **no credentials** — an address, not a
//! keychain. Identity is the structured enum (derived `Hash`/`Eq`), never a
//! stringification, so raw path bytes containing a delimiter cannot collide two
//! specs. Two text forms exist (see [`crate::uri`]): a lossless canonical URI and
//! a lossy human `Display`.

use std::path::PathBuf;

use crate::crypto::CryptoScheme;
use crate::fs::{FileId, FsKind, StreamId};
use crate::registry::ContainerFormat;
use crate::volume::VolumeScheme;

/// A 16-byte GUID (GPT partition type/id, volume identifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid(pub [u8; 16]);

/// A reference to one snapshot within a snapshot set.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnapshotRef {
    /// VSS store index.
    VssStore(usize),
    /// APFS snapshot transaction id.
    ApfsXid(u64),
}

/// How a node is addressed within a filesystem.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeAddr {
    /// Raw path components — filesystem names are bytes, not guaranteed UTF-8.
    Path(Vec<Vec<u8>>),
    /// The filesystem-specific stable id (survives a reallocated slot).
    File(FileId),
    /// Both: resolve by id, keep the observed path for context.
    Both { path: Vec<Vec<u8>>, id: FileId },
}

/// One layer in the locator chain.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Layer {
    /// The base OS path — the only parentless layer.
    Os { path: PathBuf },
    /// A byte window of the parent.
    Range { start: u64, len: u64 },
    /// Decode a container (Auto = sniffed).
    Container { format: ContainerFormat },
    /// A volume within a volume system.
    Volume {
        scheme: VolumeScheme,
        index: usize,
        guid: Option<Guid>,
    },
    /// A full-disk-encryption translation (credentials supplied out-of-band).
    Crypto { scheme: CryptoScheme },
    /// A snapshot/shadow store.
    Snapshot { store: SnapshotRef },
    /// A mounted filesystem, addressing one node.
    Fs { kind: FsKind, at: NodeAddr },
    /// A named data stream (ADS / resource fork) of the addressed node.
    Stream { id: StreamId },
}

/// The recursive locator. Constructed via [`PathSpec::os`] + [`PathSpec::push`],
/// so a new `Layer` variant is an additive change and callers never build the
/// chain by hand-nesting `Box`es.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathSpec {
    pub layer: Layer,
    pub parent: Option<Box<PathSpec>>,
}

impl PathSpec {
    /// A base spec rooted at an OS path.
    #[must_use]
    pub fn os(path: impl Into<PathBuf>) -> Self {
        Self {
            layer: Layer::Os { path: path.into() },
            parent: None,
        }
    }

    /// A raw base spec for any layer (no parent). Prefer [`PathSpec::os`] for the
    /// root; this exists for tests and re-parenting.
    #[must_use]
    pub fn root(layer: Layer) -> Self {
        Self {
            layer,
            parent: None,
        }
    }

    /// Extend the chain: `self` becomes the parent of a new node carrying `layer`.
    #[must_use]
    pub fn push(self, layer: Layer) -> Self {
        Self {
            layer,
            parent: Some(Box::new(self)),
        }
    }

    /// The number of layers in the chain (the root counts as one).
    #[must_use]
    pub fn depth(&self) -> usize {
        1 + self.parent.as_ref().map_or(0, |p| p.depth())
    }

    /// The root (parentless) spec of this chain.
    #[must_use]
    pub fn base(&self) -> &PathSpec {
        match &self.parent {
            Some(p) => p.base(),
            None => self,
        }
    }

    /// The chain from root to this node, root first.
    #[must_use]
    pub fn layers(&self) -> Vec<&Layer> {
        let mut out = match &self.parent {
            Some(p) => p.layers(),
            None => Vec::new(),
        };
        out.push(&self.layer);
        out
    }
}

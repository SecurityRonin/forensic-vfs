//! The filesystem navigation contract and its unified forensic metadata.
//!
//! One mounted, read-only filesystem is an [`Arc<dyn FileSystem>`]: all reads are
//! `&self` so N workers share one handle (no per-thread MFT re-parse), and bulk
//! enumerations are **owned, `Send`, `'static` streams** — never `&self`-borrowing
//! iterators (which cannot cross a thread boundary) and never eager `Vec`s (which
//! OOM on WinSxS-scale directories). [`FileId`] is a filesystem-specific identity,
//! not a bare inode, because a reallocated NTFS record or a reused ext inode must
//! never be confused with the original.

use std::sync::Arc;

use crate::error::VfsResult;

/// Filesystem-specific stable identity, re-exported from `forensicnomicon-core`
/// (ADR 0009). The type moved down to the zero-dep KNOWLEDGE leaf so
/// `state-history-forensic` can reuse it verbatim in the `[P]` evidential-address
/// key without a wrong-direction dependency on this VFS layer. The re-export keeps
/// every existing `forensic_vfs::FileId` import working unchanged — the address
/// domain still matches each FS's real identity primitive, so a reused slot is
/// never confused with the original.
pub use forensicnomicon_core::FileId;

/// A named data stream on a node: the default `$DATA`, an NTFS ADS, an HFS+
/// resource fork, an xattr, or synthetic slack. Metadata only — the actual runs
/// come from [`FileSystem::extents`], lazily.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamInfo {
    pub id: StreamId,
    pub name: Option<Vec<u8>>,
    pub size: u64,
    pub residency: ResidencyKind,
    pub kind: StreamKind,
}

/// Which stream of a node an operation addresses.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamId {
    Default,
    Named(u16),
    ResourceFork,
    Xattr(u16),
    Slack,
}

/// Stream taxonomy — not every named stream is an NTFS ADS; a consumer needs to
/// know what it is reading rather than flattening all streams into one bucket.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    NtfsData,
    NtfsAds,
    HfsResourceFork,
    ApfsNamed,
    Xattr,
    SyntheticSlack,
}

/// Whether a stream's bytes live inline in the metadata record or out in runs.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidencyKind {
    Resident { inline_len: u32 },
    NonResident,
}

/// Name/metadata-layer allocation status (TSK's name-vs-meta split). Run-level
/// allocation is tracked separately on [`RunInfo`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allocation {
    Allocated,
    Deleted,
    Orphan,
}

/// What kind of node this is.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Dir,
    Symlink,
    Device,
    Other,
}

/// Where a timestamp came from — an NTFS `$STANDARD_INFORMATION` time and a
/// `$FILE_NAME` time disagreeing is a tamper signal, so the source is preserved.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSource {
    /// NTFS `$STANDARD_INFORMATION`.
    Si,
    /// NTFS `$FILE_NAME`.
    Fn,
    /// A Unix inode table (ext/APFS).
    InodeTable,
    /// A directory entry (FAT/exFAT).
    DirEntry,
    /// Source not distinguished by the reader.
    Unspecified,
}

/// Native granularity of a timestamp — a UTC/seconds assumption silently loses
/// NTFS's 100 ns resolution (a tamper signal) or FAT's 2-second quantization.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeResolution {
    /// Windows FILETIME, 100 ns ticks.
    WinFileTime,
    Nanos,
    Micros,
    Seconds,
    /// FAT last-modified is quantized to 2 seconds.
    TwoSeconds,
}

/// One timestamp with its provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeStamp {
    /// Nanoseconds since the Unix epoch (i128 spans FILETIME's range).
    pub unix_nanos: i128,
    pub source: TimeSource,
    pub resolution: TimeResolution,
}

/// MAC(B) times. `None` for a field means "not present in this FS", which is
/// forensically distinct from an epoch-zero value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MacbTimes {
    pub modified: Option<TimeStamp>,
    pub accessed: Option<TimeStamp>,
    /// Metadata-change (ctime).
    pub changed: Option<TimeStamp>,
    /// Creation (crtime / born).
    pub born: Option<TimeStamp>,
}

/// How a volume's timestamps are anchored. FAT/exFAT are volume-local, so a UTC
/// assumption shifts every MAC time.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeZonePolicy {
    Utc,
    LocalUnknown,
    Local { minutes_east: i16 },
}

/// Logical/physical sector and cluster/block sizes, with per-layer provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectorSizes {
    pub logical: u32,
    pub physical: u32,
    pub cluster_or_block: u32,
}

/// Flags on one data run.
#[allow(clippy::struct_excessive_bools)] // a domain flags record, not state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunFlags {
    pub sparse: bool,
    pub encrypted: bool,
    pub compressed: bool,
    /// A filler/placeholder run (e.g. a sparse hole rendered as zeros).
    pub filler: bool,
}

/// A physical byte run in the underlying image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRun {
    pub image_offset: u64,
    pub len: u64,
    pub flags: RunFlags,
}

/// Run-level allocation — a deleted file can have partly-reallocated clusters; an
/// allocated file can have sparse holes. Independent of [`FsMeta::allocated`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunAlloc {
    Allocated,
    Unallocated,
    Overwritten,
    Unknown,
}

/// One run plus its allocation provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunInfo {
    pub run: ByteRun,
    pub alloc: RunAlloc,
}

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub id: FileId,
    pub kind: NodeKind,
}

/// A hardlink back-reference: a parent directory plus the name under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardLink {
    pub parent: FileId,
    pub name: Vec<u8>,
}

/// The unified forensic metadata record — TSK's name-layer vs meta-layer split,
/// ADS/residency, and per-timestamp provenance, **without** the eager run-list
/// (runs come from [`FileSystem::extents`] on demand).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsMeta {
    /// Metadata address (MFT reference / inode number).
    pub ino: u64,
    pub kind: NodeKind,
    /// Name/metadata-layer status.
    pub allocated: Allocation,
    pub size: u64,
    pub nlink: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u32>,
    pub times: MacbTimes,
    /// Default `$DATA` plus ADS / resource forks (metadata only).
    pub streams: Vec<StreamInfo>,
    pub residency: ResidencyKind,
    pub link_target: Option<Vec<u8>>,
}

/// A recovered deleted (or orphaned) node: the identity a consumer needs to
/// render it. Unlike the bare [`FsMeta`] that [`FileSystem::deleted`] yields,
/// this carries a readable [`FileId`] (so its bytes read via
/// [`FileSystem::read_at`] / [`FileSystem::extents`]), the recovered `name`
/// (possibly partial — a filesystem may destroy part of the name on delete,
/// e.g. FAT's `0xE5` first byte), and the `parent` directory (`None` = orphan:
/// the parent is unknown or unrecoverable). `meta` carries allocation status
/// and MACB times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedNode {
    /// Readable identity — usable with `read_at` / `extents` / `meta`.
    pub id: FileId,
    /// The recovered name. May be empty or partial when the filesystem
    /// destroyed it on delete; never fabricated.
    pub name: Vec<u8>,
    /// The parent directory, or `None` for an orphan (unrecoverable parent).
    pub parent: Option<FileId>,
    /// Allocation status ([`Allocation::Deleted`] or [`Allocation::Orphan`])
    /// plus size and MACB times.
    pub meta: FsMeta,
}

/// An owned, `Send`, `'static` stream of directory entries — holds no borrow of
/// `&self` and no lock across `next()`, so it moves to a worker thread freely.
pub struct DirStream(Box<dyn Iterator<Item = VfsResult<DirEntry>> + Send>);
/// An owned stream of allocation-tagged runs.
pub struct ExtentStream(Box<dyn Iterator<Item = VfsResult<RunInfo>> + Send>);
/// An owned stream of nodes (for deleted/orphan enumeration).
pub struct NodeStream(Box<dyn Iterator<Item = VfsResult<FsMeta>> + Send>);

impl DirStream {
    /// Wrap any `Send + 'static` iterator of entries.
    pub fn new(it: impl Iterator<Item = VfsResult<DirEntry>> + Send + 'static) -> Self {
        Self(Box::new(it))
    }
    /// An empty stream.
    #[must_use]
    pub fn empty() -> Self {
        Self(Box::new(std::iter::empty()))
    }
}
impl ExtentStream {
    pub fn new(it: impl Iterator<Item = VfsResult<RunInfo>> + Send + 'static) -> Self {
        Self(Box::new(it))
    }
    #[must_use]
    pub fn empty() -> Self {
        Self(Box::new(std::iter::empty()))
    }
}
impl NodeStream {
    pub fn new(it: impl Iterator<Item = VfsResult<FsMeta>> + Send + 'static) -> Self {
        Self(Box::new(it))
    }
    #[must_use]
    pub fn empty() -> Self {
        Self(Box::new(std::iter::empty()))
    }
}
impl Iterator for DirStream {
    type Item = VfsResult<DirEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}
impl Iterator for ExtentStream {
    type Item = VfsResult<RunInfo>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}
impl Iterator for NodeStream {
    type Item = VfsResult<FsMeta>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// An owned, `Send`, `'static` stream of [`DeletedNode`]s — the rich
/// deleted-enumeration surface (identity + name + parent), distinct from the
/// bare-[`FsMeta`] [`NodeStream`].
pub struct DeletedStream(Box<dyn Iterator<Item = VfsResult<DeletedNode>> + Send>);
impl DeletedStream {
    /// Wrap any `Send + 'static` iterator of deleted nodes.
    pub fn new(it: impl Iterator<Item = VfsResult<DeletedNode>> + Send + 'static) -> Self {
        Self(Box::new(it))
    }
    /// An empty stream — the default for a reader that cannot recover deleted
    /// identities.
    #[must_use]
    pub fn empty() -> Self {
        Self(Box::new(std::iter::empty()))
    }
}
impl Iterator for DeletedStream {
    type Item = VfsResult<DeletedNode>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// The filesystem family — the canonical identity newtype from
/// forensicnomicon-core (`FsKind::NTFS`, `FsKind::EXT`, …).
pub use forensicnomicon_core::filesystems::FsKind;

/// One mounted, read-only filesystem. Inode-addressed; `&self` reads share one
/// handle across workers; internal caches use interior mutability, never
/// `&mut self`.
pub trait FileSystem: Send + Sync {
    fn kind(&self) -> FsKind;
    fn root(&self) -> FileId;
    fn sector_sizes(&self) -> SectorSizes;
    fn timestamp_zone(&self) -> TimeZonePolicy;

    /// The filesystem's own volume label / name, decoded per the filesystem's defined
    /// encoding (NTFS `$VOLUME_NAME` UTF-16LE, FAT/exFAT label, ext4 `s_volume_name`,
    /// APFS volume name), or `None` when the volume is unlabeled or the reader does not
    /// extract it. This is the *filesystem* label (e.g. "System Reserved"), distinct
    /// from a partition-table name (`VolumeDesc.label`).
    fn volume_label(&self) -> Option<String> {
        None
    }

    /// Stream the children of a directory (owned, `Send`).
    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream>;
    /// Stream the runs of one data stream of a node (owned, `Send`).
    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream>;

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>>;
    fn meta(&self, ino: FileId) -> VfsResult<FsMeta>;
    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize>;
    /// Read a symlink target, capped so a hostile symlink cannot allocate without
    /// bound.
    fn read_link(&self, ino: FileId, cap: usize) -> VfsResult<Vec<u8>>;

    // --- Forensic surface (default-empty / streamed) ---

    fn data_streams(&self, ino: FileId) -> VfsResult<Vec<StreamInfo>> {
        let _ = ino;
        Ok(Vec::new())
    }
    /// Hardlink back-references (capped by the implementation).
    fn hardlinks(&self, ino: FileId) -> VfsResult<Vec<HardLink>> {
        let _ = ino;
        Ok(Vec::new())
    }
    /// Deleted/orphan nodes, streamed (never an eager `Vec`).
    fn deleted(&self) -> VfsResult<NodeStream>;
    /// Deleted/orphan nodes with recovered identity — a readable [`FileId`],
    /// name, and parent — so a consumer can render a deleted file in place (or
    /// route an orphan to a bucket) and read its bytes. The default is an
    /// **empty** stream: a reader opts in by overriding this once it can
    /// recover the name + parent + id from its on-disk structures (e.g. NTFS
    /// `$FILE_NAME` + the MFT reference). It never fabricates an entry. This is
    /// the surface [`deleted`](Self::deleted) cannot provide — that one yields
    /// bare [`FsMeta`] with no id to read the node.
    fn deleted_nodes(&self) -> VfsResult<DeletedStream> {
        Ok(DeletedStream::empty())
    }
    /// Unallocated runs, streamed.
    fn unallocated(&self) -> VfsResult<ExtentStream>;
    /// File slack for a stream, if the FS exposes it.
    fn slack(&self, ino: FileId, stream: StreamId) -> VfsResult<Option<ByteRun>> {
        let _ = (ino, stream);
        Ok(None)
    }

    /// Findings raised while mounting/navigating this filesystem. Behind the
    /// `findings` feature so a bare reader does not inherit forensicnomicon.
    #[cfg(feature = "findings")]
    fn findings(&self) -> VfsResult<Vec<forensicnomicon::report::Finding>> {
        Ok(Vec::new())
    }
}

/// The object-safe shared filesystem handle.
pub type DynFs = Arc<dyn FileSystem>;

//! [`VolumeSystem`] — a partitioning/volume scheme over one [`crate::ImageSource`].
//!
//! MBR/GPT/APM partitions and snapshot store-sets (VSS, APFS container) are all
//! volume systems: `volumes()` are partitions *or* stores/snapshots — the
//! libvshadow `volume → store[]` model — not special cases bolted onto a
//! filesystem. `open_volume` returns a read-only [`DynSource`] a normal
//! [`crate::fs::FileSystem`] mounts unchanged.

use crate::error::VfsResult;
use crate::source::DynSource;

/// The partitioning/volume scheme.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VolumeScheme {
    Mbr,
    Gpt,
    Apm,
    Vss,
    ApfsContainer,
    Lvm,
}

/// What one volume is.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeKind {
    Partition,
    ShadowStore,
    Snapshot,
    Unallocated,
}

/// A description of one volume within a scheme, in the parent's address space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeDesc {
    pub index: usize,
    pub kind: VolumeKind,
    pub start: u64,
    pub len: u64,
    /// GUID / type name / label hint.
    pub type_hint: Option<String>,
    pub label: Option<String>,
}

/// A partitioning/volume scheme over one [`crate::ImageSource`]. `&self` throughout.
pub trait VolumeSystem: Send + Sync {
    fn scheme(&self) -> VolumeScheme;
    /// The volumes/stores this scheme exposes.
    fn volumes(&self) -> &[VolumeDesc];
    /// A read-only byte source for one volume (a sub-range of the parent, or a
    /// snapshot-materialized source).
    fn open_volume(&self, index: usize) -> VfsResult<DynSource>;

    /// Findings raised while parsing the volume table. Behind the `findings`
    /// feature so a bare reader does not inherit forensicnomicon.
    #[cfg(feature = "findings")]
    fn findings(&self) -> VfsResult<Vec<forensicnomicon::report::Finding>> {
        Ok(Vec::new())
    }
}

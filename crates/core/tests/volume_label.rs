//! `FileSystem::volume_label()` — the defaulted filesystem-label accessor. The
//! leaf's contribution is the `None` default; a reader overrides it to surface
//! its own volume name (NTFS `$VOLUME_NAME`, FAT/exFAT label, ext4
//! `s_volume_name`, APFS volume name).
//!
//! Two doubles pin both paths of the additive accessor: `Unlabeled` does NOT
//! override it, so it must return the trait default `None`; `Labeled` overrides
//! it and must return its own value. `Labeled` fails to compile until the method
//! exists on the trait (a valid RED).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use forensic_vfs::error::VfsResult;
use forensic_vfs::fs::{
    Allocation, DirStream, DynFs, ExtentStream, FileId, FileSystem, FsKind, FsMeta, MacbTimes,
    NodeKind, NodeStream, ResidencyKind, SectorSizes, StreamId, TimeZonePolicy,
};

// The required navigation surface, identical between both doubles — only
// `volume_label` differs (present vs absent), which is the axis under test.
macro_rules! stub_fs_body {
    () => {
        fn kind(&self) -> FsKind {
            FsKind::NTFS
        }
        fn root(&self) -> FileId {
            FileId::Opaque(0)
        }
        fn sector_sizes(&self) -> SectorSizes {
            SectorSizes {
                logical: 512,
                physical: 512,
                cluster_or_block: 512,
            }
        }
        fn timestamp_zone(&self) -> TimeZonePolicy {
            TimeZonePolicy::Utc
        }
        fn read_dir(&self, _i: FileId) -> VfsResult<DirStream> {
            Ok(DirStream::empty())
        }
        fn extents(&self, _i: FileId, _s: StreamId) -> VfsResult<ExtentStream> {
            Ok(ExtentStream::empty())
        }
        fn lookup(&self, _p: FileId, _n: &[u8]) -> VfsResult<Option<FileId>> {
            Ok(None)
        }
        fn meta(&self, _i: FileId) -> VfsResult<FsMeta> {
            Ok(FsMeta {
                ino: 0,
                kind: NodeKind::Dir,
                allocated: Allocation::Allocated,
                size: 0,
                nlink: 1,
                uid: None,
                gid: None,
                mode: None,
                times: MacbTimes::default(),
                streams: Vec::new(),
                residency: ResidencyKind::NonResident,
                link_target: None,
            })
        }
        fn read_at(&self, _i: FileId, _s: StreamId, _o: u64, _b: &mut [u8]) -> VfsResult<usize> {
            Ok(0)
        }
        fn read_link(&self, _i: FileId, _c: usize) -> VfsResult<Vec<u8>> {
            Ok(Vec::new())
        }
        fn deleted(&self) -> VfsResult<NodeStream> {
            Ok(NodeStream::empty())
        }
        fn unallocated(&self) -> VfsResult<ExtentStream> {
            Ok(ExtentStream::empty())
        }
    };
}

/// Does NOT override `volume_label` — exercises the trait's `None` default.
struct Unlabeled;
impl FileSystem for Unlabeled {
    stub_fs_body!();
}

/// Overrides `volume_label` — exercises the reader-provided path.
struct Labeled;
impl FileSystem for Labeled {
    stub_fs_body!();
    fn volume_label(&self) -> Option<String> {
        Some("System Reserved".to_string())
    }
}

#[test]
fn default_volume_label_is_none() {
    let fs: DynFs = Arc::new(Unlabeled);
    assert_eq!(fs.volume_label(), None);
}

#[test]
fn overridden_volume_label_is_returned() {
    let fs: DynFs = Arc::new(Labeled);
    assert_eq!(fs.volume_label().as_deref(), Some("System Reserved"));
}

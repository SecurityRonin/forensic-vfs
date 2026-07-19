//! `deleted_nodes()` yields recovered deleted entries carrying a readable
//! [`FileId`], name, and parent — the identity a consumer needs to render a
//! deleted file in place (or route an orphan to a bucket). The default is
//! empty; a reader opts in by overriding it once it can recover the name +
//! parent + id from its on-disk structures (e.g. NTFS `$FILE_NAME` + the MFT
//! reference). This is the surface `deleted()` (bare `FsMeta`, no id) cannot
//! provide.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_vfs::error::VfsResult;
use forensic_vfs::fs::{
    Allocation, DeletedNode, DeletedStream, DirStream, ExtentStream, FileId, FileSystem, FsKind,
    FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, SectorSizes, StreamId, TimeZonePolicy,
};

fn deleted_meta(ino: u64) -> FsMeta {
    FsMeta {
        ino,
        kind: NodeKind::File,
        allocated: Allocation::Deleted,
        size: 12,
        nlink: 0,
        uid: None,
        gid: None,
        mode: None,
        times: MacbTimes::default(),
        streams: Vec::new(),
        residency: ResidencyKind::Resident { inline_len: 12 },
        link_target: None,
    }
}

fn sizes() -> SectorSizes {
    SectorSizes {
        logical: 512,
        physical: 512,
        cluster_or_block: 4096,
    }
}

/// A reader that recovers one placeable deleted node (parent known) and one
/// orphan (parent unrecoverable).
struct RecoverableFs;
impl FileSystem for RecoverableFs {
    fn kind(&self) -> FsKind {
        FsKind::NTFS
    }
    fn root(&self) -> FileId {
        FileId::NtfsRef { entry: 5, seq: 1 }
    }
    fn sector_sizes(&self) -> SectorSizes {
        sizes()
    }
    fn timestamp_zone(&self) -> TimeZonePolicy {
        TimeZonePolicy::Utc
    }
    fn read_dir(&self, _ino: FileId) -> VfsResult<DirStream> {
        Ok(DirStream::empty())
    }
    fn extents(&self, _ino: FileId, _s: StreamId) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
    fn lookup(&self, _p: FileId, _n: &[u8]) -> VfsResult<Option<FileId>> {
        Ok(None)
    }
    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let n = match ino {
            FileId::NtfsRef { entry, .. } => entry,
            _ => 0,
        };
        Ok(deleted_meta(n))
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

    fn deleted_nodes(&self) -> VfsResult<DeletedStream> {
        let placed = DeletedNode {
            id: FileId::NtfsRef { entry: 42, seq: 3 },
            name: b"notes.txt".to_vec(),
            parent: Some(FileId::NtfsRef { entry: 5, seq: 1 }),
            meta: deleted_meta(42),
        };
        let orphan = DeletedNode {
            id: FileId::NtfsRef { entry: 99, seq: 2 },
            name: b"orphan.bin".to_vec(),
            parent: None,
            meta: deleted_meta(99),
        };
        Ok(DeletedStream::new(vec![Ok(placed), Ok(orphan)].into_iter()))
    }
}

/// A reader that does NOT override `deleted_nodes()` — it must fall back to the
/// default empty stream, never a fabricated entry.
struct BareFs;
impl FileSystem for BareFs {
    fn kind(&self) -> FsKind {
        FsKind::NTFS
    }
    fn root(&self) -> FileId {
        FileId::Opaque(2)
    }
    fn sector_sizes(&self) -> SectorSizes {
        sizes()
    }
    fn timestamp_zone(&self) -> TimeZonePolicy {
        TimeZonePolicy::Utc
    }
    fn read_dir(&self, _ino: FileId) -> VfsResult<DirStream> {
        Ok(DirStream::empty())
    }
    fn extents(&self, _ino: FileId, _s: StreamId) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
    fn lookup(&self, _p: FileId, _n: &[u8]) -> VfsResult<Option<FileId>> {
        Ok(None)
    }
    fn meta(&self, _ino: FileId) -> VfsResult<FsMeta> {
        Ok(deleted_meta(0))
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
}

#[test]
fn deleted_nodes_default_is_empty() {
    let fs = BareFs;
    let got: Vec<DeletedNode> = fs.deleted_nodes().unwrap().map(Result::unwrap).collect();
    assert!(
        got.is_empty(),
        "a reader that has not implemented rich deleted recovery must yield an empty stream, never a fabricated entry"
    );
}

#[test]
fn deleted_nodes_carry_id_name_parent() {
    let fs = RecoverableFs;
    let got: Vec<DeletedNode> = fs.deleted_nodes().unwrap().map(Result::unwrap).collect();
    assert_eq!(got.len(), 2);

    // A placeable deleted node: readable id, real name, known parent.
    let placed = &got[0];
    assert_eq!(placed.id, FileId::NtfsRef { entry: 42, seq: 3 });
    assert_eq!(placed.name, b"notes.txt");
    assert_eq!(placed.parent, Some(FileId::NtfsRef { entry: 5, seq: 1 }));
    assert_eq!(placed.meta.allocated, Allocation::Deleted);

    // An orphan: no recoverable parent, but still a readable id + name.
    let orphan = &got[1];
    assert_eq!(orphan.parent, None, "an orphan has no recoverable parent");
    assert_eq!(orphan.id, FileId::NtfsRef { entry: 99, seq: 2 });
    assert_eq!(orphan.name, b"orphan.bin");
}

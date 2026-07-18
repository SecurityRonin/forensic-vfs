//! Contract + object-safety tests over the public API, as a downstream consumer
//! sees it. The load-bearing claim of the whole design is that every layer
//! composes as `Arc<dyn Trait>`; these tests instantiate a reader double for each
//! trait and drive it through its trait object, which fails to compile if any
//! trait loses object-safety.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use forensic_vfs::encryption::{Credential, CredentialSource, EncryptionLayer, EncryptionScheme};
use forensic_vfs::error::{SmallHex, VfsError, VfsResult};
use forensic_vfs::fs::{
    Allocation, DirEntry, DirStream, DynFs, ExtentStream, FileId, FileSystem, FsKind, FsMeta,
    MacbTimes, NodeKind, NodeStream, ResidencyKind, SectorSizes, StreamId, TimeZonePolicy,
};
use forensic_vfs::registry::{Confidence, Openers, SniffWindow};
use forensic_vfs::source::{
    read_exact_at, DynSource, Extent, Extents, ImageSource, SourceId, SourceView,
};
use forensic_vfs::volume::{VolumeDesc, VolumeKind, VolumeScheme, VolumeSystem};
use forensic_vfs::{Layer, PathSpec};

// --- doubles -------------------------------------------------------------

struct MemSource(Vec<u8>);
impl ImageSource for MemSource {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let off = usize::try_from(offset).unwrap_or(usize::MAX);
        let Some(src) = self.0.get(off..) else {
            return Ok(0);
        };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        Ok(n)
    }
}

struct MemFs;
impl FileSystem for MemFs {
    fn kind(&self) -> FsKind {
        FsKind::NTFS
    }
    fn root(&self) -> FileId {
        FileId::NtfsRef { entry: 5, seq: 1 }
    }
    fn sector_sizes(&self) -> SectorSizes {
        SectorSizes {
            logical: 512,
            physical: 4096,
            cluster_or_block: 4096,
        }
    }
    fn timestamp_zone(&self) -> TimeZonePolicy {
        TimeZonePolicy::Utc
    }
    fn read_dir(&self, _ino: FileId) -> VfsResult<DirStream> {
        Ok(DirStream::new(std::iter::once(Ok(DirEntry {
            name: b"file".to_vec(),
            id: FileId::Opaque(9),
            kind: NodeKind::File,
        }))))
    }
    fn extents(&self, _ino: FileId, _stream: StreamId) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
    fn lookup(&self, _parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        Ok((name == b"file").then_some(FileId::Opaque(9)))
    }
    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        Ok(FsMeta {
            ino: match ino {
                FileId::Opaque(n) => n,
                _ => 0,
            },
            kind: NodeKind::File,
            allocated: Allocation::Allocated,
            size: 4,
            nlink: 1,
            uid: Some(0),
            gid: Some(0),
            mode: Some(0o644),
            times: MacbTimes::default(),
            streams: Vec::new(),
            residency: ResidencyKind::Resident { inline_len: 4 },
            link_target: None,
        })
    }
    fn read_at(
        &self,
        _ino: FileId,
        _stream: StreamId,
        _off: u64,
        buf: &mut [u8],
    ) -> VfsResult<usize> {
        let data = b"data";
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }
    fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
        Ok(Vec::new())
    }
    fn deleted(&self) -> VfsResult<NodeStream> {
        Ok(NodeStream::empty())
    }
    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

struct OneVolume(Vec<VolumeDesc>, DynSource);
impl VolumeSystem for OneVolume {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Gpt
    }
    fn volumes(&self) -> &[VolumeDesc] {
        &self.0
    }
    fn open_volume(&self, index: usize) -> VfsResult<DynSource> {
        if index == 0 {
            Ok(self.1.clone())
        } else {
            Err(VfsError::OutOfRange {
                what: "volume",
                offset: index as u64,
                len: 1,
                bound: self.0.len() as u64,
            })
        }
    }
}

struct Vault(DynSource);
impl EncryptionLayer for Vault {
    fn scheme(&self) -> EncryptionScheme {
        EncryptionScheme::Bitlocker
    }
    fn open(&self, creds: &dyn CredentialSource) -> VfsResult<DynSource> {
        if creds
            .credentials_for(EncryptionScheme::Bitlocker, "OS")
            .is_empty()
        {
            return Err(VfsError::NeedCredentials {
                scheme: "bitlocker",
                target: "OS".to_string(),
            });
        }
        Ok(self.0.clone())
    }
}

struct Keyring(bool);
impl CredentialSource for Keyring {
    fn credentials_for(&self, _scheme: EncryptionScheme, _target: &str) -> Vec<Credential> {
        if self.0 {
            vec![Credential::Password("hunter2".to_string())]
        } else {
            Vec::new()
        }
    }
}

// --- tests ---------------------------------------------------------------

#[test]
fn image_source_composes_as_dyn_and_has_working_defaults() {
    let src: DynSource = Arc::new(MemSource(vec![1, 2, 3, 4]));
    assert_eq!(src.len(), 4);
    assert!(!src.is_empty());
    assert_eq!(src.source_id(), SourceId::ROOT);
    assert!(src.view(0, 4).is_none()); // default: no zero-copy view
                                       // default extents() is one dense run covering the whole stream
    let ext = src.extents();
    assert_eq!(ext.runs(), &[Extent { offset: 0, len: 4 }]);

    let mut buf = [0u8; 4];
    read_exact_at(src.as_ref(), 0, &mut buf).unwrap();
    assert_eq!(buf, [1, 2, 3, 4]);
    // read_exact past the end fails loud (never a partial-fill lie).
    let mut too_much = [0u8; 8];
    assert!(matches!(
        read_exact_at(src.as_ref(), 0, &mut too_much),
        Err(VfsError::OutOfRange { .. })
    ));
}

#[test]
fn filesystem_composes_as_dyn_and_drives_every_op() {
    let fs: DynFs = Arc::new(MemFs);
    assert_eq!(fs.kind(), FsKind::NTFS);
    assert!(matches!(fs.root(), FileId::NtfsRef { entry: 5, seq: 1 }));
    assert_eq!(fs.sector_sizes().logical, 512);
    assert!(matches!(fs.timestamp_zone(), TimeZonePolicy::Utc));

    let id = fs.lookup(fs.root(), b"file").unwrap().unwrap();
    assert!(fs.lookup(fs.root(), b"nope").unwrap().is_none());
    let meta = fs.meta(id).unwrap();
    assert_eq!(meta.size, 4);

    let names: Vec<_> = fs
        .read_dir(fs.root())
        .unwrap()
        .map(|e| e.unwrap().name)
        .collect();
    assert_eq!(names, vec![b"file".to_vec()]);

    let mut buf = [0u8; 4];
    assert_eq!(fs.read_at(id, StreamId::Default, 0, &mut buf).unwrap(), 4);
    assert_eq!(&buf, b"data");

    // default forensic surface
    assert!(fs.data_streams(id).unwrap().is_empty());
    assert!(fs.hardlinks(id).unwrap().is_empty());
    assert!(fs.slack(id, StreamId::Default).unwrap().is_none());
    assert!(fs.read_link(id, 64).unwrap().is_empty());
    assert_eq!(fs.extents(id, StreamId::Default).unwrap().count(), 0);
    assert_eq!(fs.deleted().unwrap().count(), 0);
    assert_eq!(fs.unallocated().unwrap().count(), 0);
}

#[test]
fn volume_system_opens_a_volume_and_rejects_out_of_range() {
    let base: DynSource = Arc::new(MemSource(vec![0xaa; 16]));
    let vs = OneVolume(
        vec![VolumeDesc {
            index: 0,
            kind: VolumeKind::Partition,
            start: 0,
            len: 16,
            type_hint: Some("EFI".to_string()),
            label: None,
        }],
        base,
    );
    let boxed: Box<dyn VolumeSystem> = Box::new(vs);
    assert_eq!(boxed.scheme(), VolumeScheme::Gpt);
    assert_eq!(boxed.volumes().len(), 1);
    assert_eq!(boxed.open_volume(0).unwrap().len(), 16);
    assert!(boxed.open_volume(1).is_err());
}

#[test]
fn encryption_layer_needs_credentials_then_opens() {
    let plain: DynSource = Arc::new(MemSource(vec![1, 2, 3]));
    let vault: Box<dyn EncryptionLayer> = Box::new(Vault(plain));
    assert_eq!(vault.scheme(), EncryptionScheme::Bitlocker);
    // No keys -> loud NeedCredentials, never a silent empty.
    assert!(matches!(
        vault.open(&Keyring(false)),
        Err(VfsError::NeedCredentials { .. })
    ));
    // With keys -> decrypted source.
    assert_eq!(vault.open(&Keyring(true)).unwrap().len(), 3);
}

#[test]
fn registry_collects_probers() {
    // An empty default registry; a real one is filled by the engine.
    let reg = Openers::new();
    assert!(reg.containers().is_empty());
    assert!(reg.volume_systems().is_empty());
    assert!(reg.encryption_layers().is_empty());
    assert!(reg.filesystems().is_empty());
}

#[test]
fn confidence_and_sniff_window() {
    assert!(Confidence::Yes { how: "magic" }.is_yes());
    assert!(Confidence::Yes { how: "magic" }.is_candidate());
    assert!(Confidence::Maybe.is_candidate());
    assert!(!Confidence::No.is_candidate());
    assert!(!Confidence::No.is_yes());

    let w = SniffWindow::new(512, &[0x4e, 0x54, 0x46, 0x53]); // "NTFS"
    assert_eq!(w.base(), 512);
    assert_eq!(w.bytes().len(), 4);
    assert!(w.has_magic(0, b"NTFS"));
    assert!(!w.has_magic(1, b"NTFS")); // out of range -> false, no panic
    assert_eq!(w.at(0, 2), Some(&[0x4e, 0x54][..]));
    assert_eq!(w.at(3, 5), None);
    assert_eq!(w.at(usize::MAX, 1), None); // overflow -> None
}

#[test]
fn sniff_window_tail_and_total_len() {
    // new(): total_len = base + bytes.len(); the tail is empty, so any
    // from-end probe declines without panic.
    let head = SniffWindow::new(0, &[1, 2, 3, 4]);
    assert_eq!(head.total_len(), 4);
    assert!(!head.has_magic_from_end(1, &[4]));
    assert_eq!(head.tail_at(1, 1), None);

    // with_tail(): a koly-like trailer sitting at file_len - tail.len(), with a
    // total_len far larger than the head window (the DMG footer case).
    let tail = [b'k', b'o', b'l', b'y', 0, 0];
    let w = SniffWindow::with_tail(0, &[0u8; 8], 1_000_000, &tail);
    assert_eq!(w.total_len(), 1_000_000);
    // "koly" starts at tail[tail.len() - 6] == tail[0].
    assert!(w.has_magic_from_end(6, b"koly"));
    assert!(!w.has_magic_from_end(6, b"KOLY"));
    assert_eq!(w.tail_at(6, 4), Some(&b"koly"[..]));
    // from_end greater than the tail length -> false/None, never a panic.
    assert!(!w.has_magic_from_end(7, b"koly"));
    assert_eq!(w.tail_at(7, 4), None);
    // n runs past the end of the tail -> None.
    assert_eq!(w.tail_at(2, 4), None);
}

#[test]
fn extents_dense_and_allocated_len() {
    assert!(Extents::dense(0).is_empty());
    let e = Extents::dense(100);
    assert_eq!(e.runs().len(), 1);
    assert_eq!(e.allocated_len(), 100);
    let sparse = Extents::from_runs(vec![
        Extent { offset: 0, len: 10 },
        Extent { offset: 50, len: 5 },
    ]);
    assert_eq!(sparse.allocated_len(), 15);
    assert!(!sparse.is_empty());
    // saturating on absurd runs
    let big = Extents::from_runs(vec![
        Extent {
            offset: 0,
            len: u64::MAX,
        },
        Extent {
            offset: 0,
            len: u64::MAX,
        },
    ]);
    assert_eq!(big.allocated_len(), u64::MAX);
}

#[test]
fn source_view_derefs_both_variants() {
    let mmap_backing = [9u8, 8, 7];
    let v = SourceView::Mmap(&mmap_backing);
    assert_eq!(&*v, &[9, 8, 7]);
    let arc: Arc<[u8]> = Arc::from([1u8, 2, 3, 4].as_slice());
    let block = SourceView::Block(arc.clone(), 1..3);
    assert_eq!(&*block, &[2, 3]);
    // An out-of-range block range degrades to empty, never panics.
    let bad = SourceView::Block(arc, 10..20);
    assert_eq!(&*bad, &[] as &[u8]);
}

#[test]
fn pathspec_navigation() {
    let spec = PathSpec::os("/img.raw")
        .push(Layer::Range { start: 0, len: 512 })
        .push(Layer::Stream {
            id: StreamId::Default,
        });
    assert_eq!(spec.depth(), 3);
    assert!(matches!(spec.base().layer, Layer::Os { .. }));
    assert_eq!(spec.layers().len(), 3);
    // a raw root spec (not OS-rooted)
    let r = PathSpec::root(Layer::Range { start: 8, len: 8 });
    assert_eq!(r.depth(), 1);
}

#[test]
fn smallhex_captures_truncates_and_formats() {
    let h = SmallHex::new(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(h.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    assert!(!h.is_empty());
    assert_eq!(format!("{h}"), "de ad be ef");
    assert_eq!(format!("{h:?}"), "SmallHex(deadbeef)");
    // longer than CAP is truncated to the identifying prefix
    let long = vec![0x41u8; 32];
    assert_eq!(SmallHex::new(&long).as_bytes().len(), SmallHex::CAP);
    assert!(SmallHex::new(&[]).is_empty());
}

#[test]
fn every_error_variant_renders() {
    let bytes = SmallHex::new(&[0x00, 0xff]);
    let errs = [
        VfsError::Io {
            op: "read",
            source: std::io::Error::other("x"),
        },
        VfsError::Decode {
            layer: "gpt",
            offset: 1,
            detail: "bad".to_string(),
            bytes,
        },
        VfsError::Unrecognized {
            at: "container",
            offset: 0,
            bytes,
        },
        VfsError::Ambiguous {
            candidates: vec!["ntfs", "fat"],
        },
        VfsError::Bootstrap {
            stage: "mount",
            detail: "no super".to_string(),
        },
        VfsError::Unsupported {
            layer: "encryption",
            scheme: "veracrypt".to_string(),
        },
        VfsError::Budget {
            cap: "depth",
            limit: 16,
        },
        VfsError::NeedCredentials {
            scheme: "luks2",
            target: "root".to_string(),
        },
        VfsError::OutOfRange {
            what: "read",
            offset: 9,
            len: 4,
            bound: 8,
        },
    ];
    for e in errs {
        assert!(!format!("{e}").is_empty());
    }
}

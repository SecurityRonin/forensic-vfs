//! Completion tests exercising the behavioral surface the contract/behavioral
//! tests don't reach: every token variant round-trips, the Openers builder, the
//! SourceId accessors, the stream constructors, and (under the findings feature)
//! the default findings() surface.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use forensic_vfs::adapters::{SourceCursor, SubRange};
use forensic_vfs::encryption::EncryptionScheme;
use forensic_vfs::error::VfsResult;
use forensic_vfs::fs::{ByteRun, ExtentStream, FsKind, NodeStream, RunAlloc, RunFlags, RunInfo};
use forensic_vfs::registry::{
    ArchiveOpen, ContainerFormat, ContainerOpen, EncryptionOpen, FileSystemOpen, Openers,
    SniffWindow, VolumeSystemOpen,
};
use forensic_vfs::source::{DynSource, ImageSource, SourceId};
use forensic_vfs::volume::VolumeScheme;
use forensic_vfs::{ArchiveContents, Member};
use forensic_vfs::{Layer, NodeAddr, PathSpec};

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
    fn source_id(&self) -> SourceId {
        SourceId::new(42)
    }
}

fn uri_round_trips(spec: &PathSpec) {
    let back = PathSpec::from_uri(&spec.to_uri()).unwrap();
    assert_eq!(&back, spec);
}

#[test]
fn both_addr_with_empty_path_round_trips() {
    use forensic_vfs::fs::FileId;
    // A `Both` with no observed path components — the id-only branch.
    uri_round_trips(&PathSpec::os("/x").push(Layer::Fs {
        kind: FsKind::NTFS,
        at: NodeAddr::Both {
            path: vec![],
            id: FileId::NtfsRef { entry: 3, seq: 1 },
        },
    }));
}

#[test]
fn every_container_format_token_round_trips() {
    for f in [
        ContainerFormat::Ewf,
        ContainerFormat::Vmdk,
        ContainerFormat::Vhdx,
        ContainerFormat::Vhd,
        ContainerFormat::Qcow2,
        ContainerFormat::Dmg,
        ContainerFormat::Aff4,
        ContainerFormat::Ad1,
        ContainerFormat::Dar,
        ContainerFormat::Raw,
        ContainerFormat::Auto,
    ] {
        uri_round_trips(&PathSpec::os("/x").push(Layer::Container { format: f }));
    }
}

#[test]
fn every_volume_scheme_token_round_trips() {
    for (i, s) in [
        VolumeScheme::Mbr,
        VolumeScheme::Gpt,
        VolumeScheme::Apm,
        VolumeScheme::Vss,
        VolumeScheme::ApfsContainer,
        VolumeScheme::Lvm,
    ]
    .into_iter()
    .enumerate()
    {
        uri_round_trips(&PathSpec::os("/x").push(Layer::Volume {
            scheme: s,
            index: i,
            guid: None,
        }));
    }
}

#[test]
fn every_encryption_scheme_token_round_trips() {
    for s in [
        EncryptionScheme::Bitlocker,
        EncryptionScheme::Luks1,
        EncryptionScheme::Luks2,
        EncryptionScheme::FileVault,
        EncryptionScheme::ApfsEncrypted,
        EncryptionScheme::VeraCrypt,
    ] {
        uri_round_trips(&PathSpec::os("/x").push(Layer::Encryption { scheme: s }));
    }
}

#[test]
fn every_fs_kind_token_round_trips() {
    // Every registered kind of the string-backed newtype must survive the
    // fs-locator token round-trip (the `as_str` / `parse_fs_kind` pair).
    for &k in FsKind::known() {
        uri_round_trips(&PathSpec::os("/x").push(Layer::Fs {
            kind: k,
            at: NodeAddr::Path(vec![b"a".to_vec()]),
        }));
    }
}

// --- Openers builder: minimal probe doubles ---

struct Dc;
impl ContainerOpen for Dc {
    fn format(&self) -> ContainerFormat {
        ContainerFormat::Raw
    }
    fn probe(&self, _w: &SniffWindow) -> forensic_vfs::Confidence {
        forensic_vfs::Confidence::No
    }
    fn open(&self, src: DynSource) -> VfsResult<DynSource> {
        Ok(src)
    }
}
struct Vp;
impl VolumeSystemOpen for Vp {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Mbr
    }
    fn probe(&self, _w: &SniffWindow) -> forensic_vfs::Confidence {
        forensic_vfs::Confidence::No
    }
    fn open(&self, _src: DynSource) -> VfsResult<Box<dyn forensic_vfs::volume::VolumeSystem>> {
        Err(forensic_vfs::VfsError::Unsupported {
            layer: "vol",
            scheme: "test".to_string(),
        })
    }
}
struct Cp;
impl EncryptionOpen for Cp {
    fn scheme(&self) -> EncryptionScheme {
        EncryptionScheme::Luks1
    }
    fn probe(&self, _w: &SniffWindow) -> forensic_vfs::Confidence {
        forensic_vfs::Confidence::No
    }
    fn open(
        &self,
        _src: DynSource,
    ) -> VfsResult<Box<dyn forensic_vfs::encryption::EncryptionLayer>> {
        Err(forensic_vfs::VfsError::Unsupported {
            layer: "encryption",
            scheme: "test".to_string(),
        })
    }
}
struct Fp;
impl FileSystemOpen for Fp {
    fn kind(&self) -> FsKind {
        FsKind::FAT
    }
    fn probe(&self, _w: &SniffWindow) -> forensic_vfs::Confidence {
        forensic_vfs::Confidence::No
    }
    fn open(&self, _src: DynSource) -> VfsResult<forensic_vfs::fs::DynFs> {
        Err(forensic_vfs::VfsError::Unsupported {
            layer: "fs",
            scheme: "test".to_string(),
        })
    }
}
struct Ap;
impl ArchiveOpen for Ap {
    fn probe(&self, _w: &SniffWindow) -> forensic_vfs::Confidence {
        forensic_vfs::Confidence::No
    }
    fn open(&self, src: DynSource) -> VfsResult<ArchiveContents> {
        Ok(ArchiveContents::Stream(src))
    }
}

#[test]
fn registry_builder_registers_each_kind() {
    let reg = Openers::new()
        .container(Dc)
        .volume_system(Vp)
        .encryption(Cp)
        .filesystem(Fp)
        .archive(Ap);
    assert_eq!(reg.containers().len(), 1);
    assert_eq!(reg.volume_systems().len(), 1);
    assert_eq!(reg.encryption_layers().len(), 1);
    assert_eq!(reg.filesystems().len(), 1);
    assert_eq!(reg.archives().len(), 1);
    assert_eq!(reg.containers()[0].format(), ContainerFormat::Raw);
}

#[test]
fn archive_open_is_object_safe_and_contents_constructs_both_variants() {
    // `ArchiveOpen` must be usable as a trait object (the `Openers` table holds
    // `Box<dyn ArchiveOpen>`), and `ArchiveContents` must construct both arms.
    let ao: Box<dyn ArchiveOpen> = Box::new(Ap);
    let src: DynSource = Arc::new(MemSource(vec![1, 2, 3, 4]));
    let ArchiveContents::Stream(s) = ao.open(src).unwrap() else {
        panic!("Ap yields a Stream");
    };
    assert_eq!(s.len(), 4);
    let members = ArchiveContents::Members(vec![Member {
        name: b"inner.E01".to_vec(),
        source: Arc::new(MemSource(vec![0u8; 8])),
    }]);
    let ArchiveContents::Members(m) = members else {
        panic!("constructed Members");
    };
    assert_eq!(m[0].name, b"inner.E01");
    assert_eq!(m[0].source.len(), 8);
}

#[test]
fn source_id_accessors() {
    assert_eq!(SourceId::ROOT.get(), 0);
    assert_eq!(SourceId::new(7).get(), 7);
    assert_eq!(SourceId::default(), SourceId::ROOT);
    // SubRange inherits the parent's lineage.
    let parent: DynSource = Arc::new(MemSource(vec![0; 8]));
    let sr = SubRange::new(parent, 0, 8);
    assert_eq!(sr.source_id(), SourceId::new(42));
}

#[test]
fn stream_constructors_yield_items() {
    let run = RunInfo {
        run: ByteRun {
            image_offset: 0,
            len: 16,
            flags: RunFlags::default(),
        },
        alloc: RunAlloc::Allocated,
    };
    let ext = ExtentStream::new(std::iter::once(Ok(run)));
    assert_eq!(ext.count(), 1);
    let nodes = NodeStream::new(std::iter::empty());
    assert_eq!(nodes.count(), 0);
    assert_eq!(forensic_vfs::fs::DirStream::empty().count(), 0);
}

#[test]
fn from_uri_rejects_every_malformed_layer() {
    for bad in [
        "no-scheme",
        "fvfs:",
        "fvfs:notag",
        "fvfs:bogus:x",
        "fvfs:os:%2",  // truncated percent
        "fvfs:os:%zz", // bad percent hex
        "fvfs:os:x|container:zzz",
        "fvfs:os:x|range:5",   // missing ,len
        "fvfs:os:x|range:a,b", // non-numeric
        "fvfs:os:x|volume:zzz,0",
        "fvfs:os:x|volume:gpt",            // missing index
        "fvfs:os:x|volume:gpt,0,tooshort", // bad guid len
        "fvfs:os:x|volume:gpt,0,zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // 32 non-hex
        "fvfs:os:x|encryption:zzz",
        "fvfs:os:x|snapshot:zzz,1",
        "fvfs:os:x|snapshot:vss",          // missing ,id
        "fvfs:os:x|fs:zzz,p",              // bad fs kind
        "fvfs:os:x|fs:ntfs",               // missing addr
        "fvfs:os:x|fs:ntfs,zzz",           // bad node-addr tag
        "fvfs:os:x|fs:ntfs,f/zzz.1",       // bad file-id kind
        "fvfs:os:x|fs:ntfs,f/ntfsref",     // file id missing fields
        "fvfs:os:x|fs:ntfs,f/ntfsref.x.1", // file id non-numeric
        "fvfs:os:x|stream:zzz",
        "fvfs:os:x|archive:notanumber", // archive member index must be numeric
    ] {
        assert!(PathSpec::from_uri(bad).is_err(), "should reject: {bad}");
    }
}

#[test]
fn display_renders_every_layer_kind() {
    use forensic_vfs::fs::{FileId, StreamId};
    use forensic_vfs::pathspec::SnapshotRef;
    let spec = PathSpec::os("/img.raw")
        .push(Layer::Range { start: 0, len: 512 })
        .push(Layer::Volume {
            scheme: VolumeScheme::Gpt,
            index: 2,
            guid: None,
        })
        .push(Layer::Encryption {
            scheme: EncryptionScheme::Luks2,
        })
        .push(Layer::Snapshot {
            store: SnapshotRef::VssStore(1),
        })
        .push(Layer::Fs {
            kind: FsKind::NTFS,
            at: NodeAddr::File(FileId::NtfsRef { entry: 5, seq: 1 }),
        })
        .push(Layer::Stream {
            id: StreamId::Named(3),
        })
        .push(Layer::Archive { member: Some(2) });
    let human = format!("{spec}");
    for needle in [
        "range[0+512]",
        "gpt#2",
        "luks2",
        "vss#1",
        "ntfs#",
        ":named.3",
        "archive#2",
    ] {
        assert!(human.contains(needle), "missing {needle} in {human}");
    }
    // The bare-stream (member: None) archive Display arm.
    let stream = PathSpec::os("/x").push(Layer::Archive { member: None });
    assert!(format!("{stream}").contains("archive"));
    // The apfs snapshot Display arm.
    let apfs = PathSpec::os("/x").push(Layer::Snapshot {
        store: SnapshotRef::ApfsXid(77),
    });
    assert!(format!("{apfs}").contains("apfs@77"));
}

#[test]
fn sourcecursor_current_and_negative_seek() {
    let base: DynSource = Arc::new(MemSource(vec![0, 1, 2, 3, 4, 5]));
    let mut cur = SourceCursor::new(base, 0, 6);
    let mut one = [0u8; 2];
    cur.read_exact(&mut one).unwrap();
    // Current-relative seek.
    assert_eq!(cur.seek(SeekFrom::Current(1)).unwrap(), 3);
    // Negative seek before the window start is a loud error, not a wrap.
    assert!(cur.seek(SeekFrom::Current(-100)).is_err());
    assert!(cur.seek(SeekFrom::Start(2)).is_ok());
}

#[cfg(feature = "findings")]
#[test]
fn findings_default_surfaces_are_empty() {
    use forensic_vfs::encryption::{CredentialSource, EncryptionLayer};
    use forensic_vfs::fs::{
        Allocation, DirStream, DynFs, FileId, FileSystem, FsMeta, MacbTimes, NodeKind,
        ResidencyKind, SectorSizes, StreamId, TimeZonePolicy,
    };
    use forensic_vfs::volume::{VolumeDesc, VolumeSystem};

    struct F;
    impl FileSystem for F {
        fn kind(&self) -> FsKind {
            FsKind::BTRFS
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
            TimeZonePolicy::LocalUnknown
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
    }
    struct V;
    impl VolumeSystem for V {
        fn scheme(&self) -> VolumeScheme {
            VolumeScheme::Mbr
        }
        fn volumes(&self) -> &[VolumeDesc] {
            &[]
        }
        fn open_volume(&self, _i: usize) -> VfsResult<DynSource> {
            Ok(Arc::new(MemSource(Vec::new())))
        }
    }

    struct C;
    impl EncryptionLayer for C {
        fn scheme(&self) -> EncryptionScheme {
            EncryptionScheme::FileVault
        }
        fn open(&self, _c: &dyn CredentialSource) -> VfsResult<DynSource> {
            Ok(Arc::new(MemSource(Vec::new())))
        }
    }

    let fs: DynFs = Arc::new(F);
    assert!(fs.findings().unwrap().is_empty());
    assert!(V.findings().unwrap().is_empty());
    assert!(C.findings().unwrap().is_empty());
}

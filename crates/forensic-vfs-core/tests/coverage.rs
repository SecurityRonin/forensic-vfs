//! Completion tests exercising the behavioral surface the contract/behavioral
//! tests don't reach: every token variant round-trips, the Registry builder, the
//! SourceId accessors, the stream constructors, and (under the findings feature)
//! the default findings() surface.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use forensic_vfs_core::adapters::{SourceCursor, SubRange};
use forensic_vfs_core::crypto::CryptoScheme;
use forensic_vfs_core::error::VfsResult;
use forensic_vfs_core::fs::{
    ByteRun, ExtentStream, FsKind, NodeStream, RunAlloc, RunFlags, RunInfo,
};
use forensic_vfs_core::registry::{
    ContainerDecoder, ContainerFormat, CryptoProbe, FileSystemProbe, Registry, SniffWindow,
    VolumeSystemProbe,
};
use forensic_vfs_core::source::{DynSource, ImageSource, SourceId};
use forensic_vfs_core::volume::VolumeScheme;
use forensic_vfs_core::{Layer, NodeAddr, PathSpec};

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
    use forensic_vfs_core::fs::FileId;
    // A `Both` with no observed path components — the id-only branch.
    uri_round_trips(&PathSpec::os("/x").push(Layer::Fs {
        kind: FsKind::Ntfs,
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
fn every_crypto_scheme_token_round_trips() {
    for s in [
        CryptoScheme::Bitlocker,
        CryptoScheme::Luks1,
        CryptoScheme::Luks2,
        CryptoScheme::FileVault,
        CryptoScheme::ApfsEncrypted,
    ] {
        uri_round_trips(&PathSpec::os("/x").push(Layer::Crypto { scheme: s }));
    }
}

#[test]
fn every_fs_kind_token_round_trips() {
    for k in [
        FsKind::Ntfs,
        FsKind::Ext,
        FsKind::HfsPlus,
        FsKind::Apfs,
        FsKind::Iso9660,
        FsKind::Udf,
        FsKind::Fat,
        FsKind::ExFat,
        FsKind::Other,
    ] {
        uri_round_trips(&PathSpec::os("/x").push(Layer::Fs {
            kind: k,
            at: NodeAddr::Path(vec![b"a".to_vec()]),
        }));
    }
}

// --- Registry builder: minimal probe doubles ---

struct Dc;
impl ContainerDecoder for Dc {
    fn format(&self) -> ContainerFormat {
        ContainerFormat::Raw
    }
    fn probe(&self, _w: &SniffWindow) -> forensic_vfs_core::Confidence {
        forensic_vfs_core::Confidence::No
    }
    fn open(&self, src: DynSource) -> VfsResult<DynSource> {
        Ok(src)
    }
}
struct Vp;
impl VolumeSystemProbe for Vp {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Mbr
    }
    fn probe(&self, _w: &SniffWindow) -> forensic_vfs_core::Confidence {
        forensic_vfs_core::Confidence::No
    }
    fn open(&self, _src: DynSource) -> VfsResult<Box<dyn forensic_vfs_core::volume::VolumeSystem>> {
        Err(forensic_vfs_core::VfsError::Unsupported {
            layer: "vol",
            scheme: "test".to_string(),
        })
    }
}
struct Cp;
impl CryptoProbe for Cp {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Luks1
    }
    fn probe(&self, _w: &SniffWindow) -> forensic_vfs_core::Confidence {
        forensic_vfs_core::Confidence::No
    }
    fn open(&self, _src: DynSource) -> VfsResult<Box<dyn forensic_vfs_core::crypto::CryptoLayer>> {
        Err(forensic_vfs_core::VfsError::Unsupported {
            layer: "crypto",
            scheme: "test".to_string(),
        })
    }
}
struct Fp;
impl FileSystemProbe for Fp {
    fn kind(&self) -> FsKind {
        FsKind::Fat
    }
    fn probe(&self, _w: &SniffWindow) -> forensic_vfs_core::Confidence {
        forensic_vfs_core::Confidence::No
    }
    fn open(&self, _src: DynSource) -> VfsResult<forensic_vfs_core::fs::DynFs> {
        Err(forensic_vfs_core::VfsError::Unsupported {
            layer: "fs",
            scheme: "test".to_string(),
        })
    }
}

#[test]
fn registry_builder_registers_each_kind() {
    let reg = Registry::new()
        .container(Dc)
        .volume_system(Vp)
        .crypto(Cp)
        .filesystem(Fp);
    assert_eq!(reg.containers().len(), 1);
    assert_eq!(reg.volume_systems().len(), 1);
    assert_eq!(reg.crypto_layers().len(), 1);
    assert_eq!(reg.filesystems().len(), 1);
    assert_eq!(reg.containers()[0].format(), ContainerFormat::Raw);
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
    assert_eq!(forensic_vfs_core::fs::DirStream::empty().count(), 0);
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
        "fvfs:os:x|crypto:zzz",
        "fvfs:os:x|snapshot:zzz,1",
        "fvfs:os:x|snapshot:vss",          // missing ,id
        "fvfs:os:x|fs:zzz,p",              // bad fs kind
        "fvfs:os:x|fs:ntfs",               // missing addr
        "fvfs:os:x|fs:ntfs,zzz",           // bad node-addr tag
        "fvfs:os:x|fs:ntfs,f/zzz.1",       // bad file-id kind
        "fvfs:os:x|fs:ntfs,f/ntfsref",     // file id missing fields
        "fvfs:os:x|fs:ntfs,f/ntfsref.x.1", // file id non-numeric
        "fvfs:os:x|stream:zzz",
    ] {
        assert!(PathSpec::from_uri(bad).is_err(), "should reject: {bad}");
    }
}

#[test]
fn display_renders_every_layer_kind() {
    use forensic_vfs_core::fs::{FileId, StreamId};
    use forensic_vfs_core::pathspec::SnapshotRef;
    let spec = PathSpec::os("/img.raw")
        .push(Layer::Range { start: 0, len: 512 })
        .push(Layer::Volume {
            scheme: VolumeScheme::Gpt,
            index: 2,
            guid: None,
        })
        .push(Layer::Crypto {
            scheme: CryptoScheme::Luks2,
        })
        .push(Layer::Snapshot {
            store: SnapshotRef::VssStore(1),
        })
        .push(Layer::Fs {
            kind: FsKind::Ntfs,
            at: NodeAddr::File(FileId::NtfsRef { entry: 5, seq: 1 }),
        })
        .push(Layer::Stream {
            id: StreamId::Named(3),
        });
    let human = format!("{spec}");
    for needle in [
        "range[0+512]",
        "gpt#2",
        "luks2",
        "vss#1",
        "ntfs#",
        ":named.3",
    ] {
        assert!(human.contains(needle), "missing {needle} in {human}");
    }
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
    use forensic_vfs_core::crypto::{CredentialSource, CryptoLayer};
    use forensic_vfs_core::fs::{
        Allocation, DirStream, DynFs, FileId, FileSystem, FsMeta, MacbTimes, NodeKind,
        ResidencyKind, SectorSizes, StreamId, TimeZonePolicy,
    };
    use forensic_vfs_core::volume::{VolumeDesc, VolumeSystem};

    struct F;
    impl FileSystem for F {
        fn kind(&self) -> FsKind {
            FsKind::Other
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
    impl CryptoLayer for C {
        fn scheme(&self) -> CryptoScheme {
            CryptoScheme::FileVault
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

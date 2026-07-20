//! Generic resolver tests: drive the [`SourceOpen`] extension trait, `walk`, and the
//! snapshot view helpers with **fake probers over synthetic sources** — no
//! concrete reader. These exercise every branch of the generic resolver (the
//! reader-wired `Vfs`/`default_registry` path stays in the orchestration layer).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use forensic_vfs::adapters::SubRange;
use forensic_vfs::{
    Allocation, ArchiveContents, ArchiveOpen, Confidence, ContainerFormat, ContainerOpen,
    CredentialSource, DirEntry, DirStream, DynFs, DynSource, EncryptionLayer, EncryptionOpen,
    EncryptionScheme, FileId, FileSystem, FileSystemOpen, FsKind, FsMeta, ImageSource, Layer,
    Locator, MacbTimes, Member, NoCredentials, NodeAddr, NodeKind, Openers, ResidencyKind,
    SectorSizes, SnapshotRef, SniffWindow, TimeZonePolicy, VfsError, VfsResult, VolumeDesc,
    VolumeKind, VolumeScheme, VolumeSystem, VolumeSystemOpen,
};
use forensic_vfs_resolver::{
    epoch_from_create_time, snapshot_view, walk, Evidence, ResolvedSource, SourceOpen,
};

// --- doubles -------------------------------------------------------------

/// One directory's children: `(name, child_id, kind)`.
type Children = Vec<(Vec<u8>, u64, NodeKind)>;
/// A fixed filesystem tree: `id -> children`.
type Tree = Vec<(u64, Children)>;

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
fn mem(bytes: Vec<u8>) -> DynSource {
    Arc::new(MemSource(bytes))
}

/// A trivial mounted filesystem whose children come from a fixed tree keyed by
/// the node's `Opaque` id: `id -> [(name, child_id, kind)]`.
struct TreeFs {
    tree: Tree,
}
impl TreeFs {
    fn children(&self, id: u64) -> &[(Vec<u8>, u64, NodeKind)] {
        self.tree
            .iter()
            .find(|(k, _)| *k == id)
            .map_or(&[], |(_, v)| v.as_slice())
    }
}
impl FileSystem for TreeFs {
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
    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let id = match ino {
            FileId::Opaque(n) => n,
            _ => 0,
        };
        let kids: Vec<VfsResult<DirEntry>> = self
            .children(id)
            .iter()
            .map(|(name, cid, kind)| {
                Ok(DirEntry {
                    name: name.clone(),
                    id: FileId::Opaque(*cid),
                    kind: *kind,
                })
            })
            .collect();
        Ok(DirStream::new(kids.into_iter()))
    }
    fn extents(
        &self,
        _ino: FileId,
        _stream: forensic_vfs::StreamId,
    ) -> VfsResult<forensic_vfs::ExtentStream> {
        Ok(forensic_vfs::ExtentStream::empty())
    }
    fn lookup(&self, _parent: FileId, _name: &[u8]) -> VfsResult<Option<FileId>> {
        Ok(None)
    }
    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let id = match ino {
            FileId::Opaque(n) => n,
            _ => 0,
        };
        // The node's kind is whatever its parent recorded; the root is a dir.
        let kind = if id == 0 {
            NodeKind::Dir
        } else {
            self.tree
                .iter()
                .flat_map(|(_, v)| v.iter())
                .find(|(_, cid, _)| *cid == id)
                .map_or(NodeKind::File, |(_, _, k)| *k)
        };
        Ok(FsMeta {
            ino: id,
            kind,
            allocated: Allocation::Allocated,
            size: 0,
            nlink: 1,
            uid: None,
            gid: None,
            mode: None,
            times: MacbTimes::default(),
            streams: Vec::new(),
            residency: ResidencyKind::Resident { inline_len: 0 },
            link_target: None,
        })
    }
    fn read_at(
        &self,
        _ino: FileId,
        _stream: forensic_vfs::StreamId,
        _off: u64,
        _buf: &mut [u8],
    ) -> VfsResult<usize> {
        Ok(0)
    }
    fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
        Ok(Vec::new())
    }
    fn deleted(&self) -> VfsResult<forensic_vfs::NodeStream> {
        Ok(forensic_vfs::NodeStream::empty())
    }
    fn unallocated(&self) -> VfsResult<forensic_vfs::ExtentStream> {
        Ok(forensic_vfs::ExtentStream::empty())
    }
}

/// A filesystem prober that says `Yes` when the head begins with `magic` and
/// mounts a fixed `TreeFs`. `fail` makes `open` return a loud error even after a
/// `Yes` verdict (the "magic but garbage body" case).
struct FakeFsProbe {
    magic: &'static [u8],
    fail: bool,
}
impl FileSystemOpen for FakeFsProbe {
    fn kind(&self) -> FsKind {
        FsKind::NTFS
    }
    fn probe(&self, w: &SniffWindow) -> Confidence {
        if w.has_magic(0, self.magic) {
            Confidence::Yes { how: "fake fs" }
        } else {
            Confidence::No
        }
    }
    fn open(&self, _src: DynSource) -> VfsResult<DynFs> {
        if self.fail {
            return Err(VfsError::Decode {
                layer: "fakefs",
                offset: 0,
                detail: "garbage body".to_string(),
                bytes: forensic_vfs::SmallHex::new(&[]),
            });
        }
        Ok(Arc::new(TreeFs {
            tree: vec![
                (
                    0,
                    vec![
                        (b"dir".to_vec(), 1, NodeKind::Dir),
                        (b"a.txt".to_vec(), 2, NodeKind::File),
                    ],
                ),
                (1, vec![(b"b.txt".to_vec(), 3, NodeKind::File)]),
            ],
        }))
    }
}

/// A volume system exposing sub-ranges of its parent at fixed `(start,len)`.
struct FakeVs {
    parent: DynSource,
    descs: Vec<VolumeDesc>,
}
impl VolumeSystem for FakeVs {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Gpt
    }
    fn volumes(&self) -> &[VolumeDesc] {
        &self.descs
    }
    fn open_volume(&self, index: usize) -> VfsResult<DynSource> {
        let d = self.descs.get(index).ok_or(VfsError::OutOfRange {
            what: "fake volume",
            offset: index as u64,
            len: 1,
            bound: self.descs.len() as u64,
        })?;
        Ok(Arc::new(SubRange::new(self.parent.clone(), d.start, d.len)))
    }
}

/// A volume-system prober keyed on a head magic; each volume is a 512-byte window.
struct FakeVsProbe {
    magic: &'static [u8],
    windows: Vec<(u64, u64)>,
}
impl VolumeSystemOpen for FakeVsProbe {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Gpt
    }
    fn probe(&self, w: &SniffWindow) -> Confidence {
        if w.has_magic(0, self.magic) {
            Confidence::Yes { how: "fake vs" }
        } else {
            Confidence::No
        }
    }
    fn open(&self, src: DynSource) -> VfsResult<Box<dyn VolumeSystem>> {
        let descs = self
            .windows
            .iter()
            .enumerate()
            .map(|(i, (start, len))| VolumeDesc {
                index: i,
                kind: VolumeKind::Partition,
                start: *start,
                len: *len,
                type_hint: None,
                label: None,
            })
            .collect();
        Ok(Box::new(FakeVs { parent: src, descs }))
    }
}

/// A container decoder keyed on a head magic that decodes to a fixed sub-window
/// of the same source (models an image whose payload sits at an inner offset).
struct FakeContainer {
    magic: &'static [u8],
    inner: (u64, u64),
    tail: bool,
}
impl ContainerOpen for FakeContainer {
    fn format(&self) -> ContainerFormat {
        ContainerFormat::Raw
    }
    fn probe(&self, w: &SniffWindow) -> Confidence {
        let hit = if self.tail {
            w.has_magic_from_end(self.magic.len(), self.magic)
        } else {
            w.has_magic(0, self.magic)
        };
        if hit {
            Confidence::Yes {
                how: "fake container",
            }
        } else {
            Confidence::No
        }
    }
    fn open(&self, src: DynSource) -> VfsResult<DynSource> {
        Ok(Arc::new(SubRange::new(src, self.inner.0, self.inner.1)))
    }
}

/// An archive peeler keyed on a head magic. `members = false` yields a 1→1
/// [`ArchiveContents::Stream`] over a sub-window of the source (a bare gz/bz2
/// wrapper); `members = true` yields a single-entry
/// [`ArchiveContents::Members`] whose member is that same sub-window (an
/// evidence file inside a tar/zip/7z).
struct FakeArchive {
    magic: &'static [u8],
    members: bool,
    inner: (u64, u64),
}
impl ArchiveOpen for FakeArchive {
    fn probe(&self, w: &SniffWindow) -> Confidence {
        if w.has_magic(0, self.magic) {
            Confidence::Yes {
                how: "fake archive",
            }
        } else {
            Confidence::No
        }
    }
    fn open(&self, src: DynSource) -> VfsResult<ArchiveContents> {
        let inner: DynSource = Arc::new(SubRange::new(src, self.inner.0, self.inner.1));
        if self.members {
            Ok(ArchiveContents::Members(vec![Member {
                name: b"case.img".to_vec(),
                source: inner,
            }]))
        } else {
            Ok(ArchiveContents::Stream(inner))
        }
    }
}

/// The FDE detection model a [`FakeEncProbe`] emulates.
enum FakeVerdict {
    /// Signature-detectable (BitLocker/LUKS/FileVault): `probe` returns
    /// `Yes` on the head magic.
    Signature(&'static [u8]),
    /// Signature-less (VeraCrypt): `probe` can only ever return `Maybe`.
    CredentialAttempt,
}

/// The decrypted view a fake encryption layer presents. `open(creds)` yields a
/// sub-window of the ciphertext source when `inner` is `Some` (a successful
/// decrypt), and errors loud when `None` (a bad/absent key).
struct FakeEncLayer {
    scheme: EncryptionScheme,
    src: DynSource,
    inner: Option<(u64, u64)>,
    attempts: Arc<Mutex<usize>>,
}
impl EncryptionLayer for FakeEncLayer {
    fn scheme(&self) -> EncryptionScheme {
        self.scheme
    }
    fn open(&self, _creds: &dyn CredentialSource) -> VfsResult<DynSource> {
        *self.attempts.lock().unwrap() += 1;
        match self.inner {
            Some((start, len)) => Ok(Arc::new(SubRange::new(self.src.clone(), start, len))),
            None => Err(VfsError::Decode {
                layer: "fake-enc",
                offset: 0,
                detail: "bad key".to_string(),
                bytes: forensic_vfs::SmallHex::new(&[]),
            }),
        }
    }
}

/// An encryption prober in one of the two FDE models. `attempts` counts the
/// number of times its layer's `open(creds)` decrypt was actually driven, so a
/// test can assert a credential-attempt scheme was (or was not) reached.
struct FakeEncProbe {
    scheme: EncryptionScheme,
    verdict: FakeVerdict,
    inner: Option<(u64, u64)>,
    attempts: Arc<Mutex<usize>>,
}
impl EncryptionOpen for FakeEncProbe {
    fn scheme(&self) -> EncryptionScheme {
        self.scheme
    }
    fn probe(&self, w: &SniffWindow) -> Confidence {
        match self.verdict {
            FakeVerdict::Signature(magic) => {
                if w.has_magic(0, magic) {
                    Confidence::Yes { how: "fake enc" }
                } else {
                    Confidence::No
                }
            }
            FakeVerdict::CredentialAttempt => Confidence::Maybe,
        }
    }
    fn open(&self, src: DynSource) -> VfsResult<Box<dyn EncryptionLayer>> {
        Ok(Box::new(FakeEncLayer {
            scheme: self.scheme,
            src,
            inner: self.inner,
            attempts: self.attempts.clone(),
        }))
    }
}

// --- resolve branches ----------------------------------------------------

#[test]
fn resolves_a_filesystem_at_the_top_layer() {
    let reg = Openers::new().filesystem(FakeFsProbe {
        magic: b"FSFS",
        fail: false,
    });
    let mut data = b"FSFS".to_vec();
    data.resize(8192, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let out = reg.open(mem(data), base, 0).unwrap().expect("mounts fs");
    // The locator gains an fs: layer at the empty path.
    assert!(matches!(
        out.spec.layer,
        Layer::Fs {
            kind: FsKind::NTFS,
            at: NodeAddr::Path(_)
        }
    ));
    assert_eq!(out.fs.kind(), FsKind::NTFS);
}

#[test]
fn a_matching_probe_whose_open_fails_propagates_loud() {
    let reg = Openers::new().filesystem(FakeFsProbe {
        magic: b"FSFS",
        fail: true,
    });
    let mut data = b"FSFS".to_vec();
    data.resize(8192, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    assert!(reg.open(mem(data), base, 0).is_err());
}

#[test]
fn descends_a_volume_system_into_its_filesystem() {
    // A volume system whose single partition (at offset 512) holds the fs magic.
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .volume_system(FakeVsProbe {
            magic: b"VOLS",
            windows: vec![(512, 4096)],
        });
    let mut data = b"VOLS".to_vec();
    data.resize(512, 0);
    data.extend_from_slice(b"FSFS");
    data.resize(8192, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let out = reg
        .open(mem(data), base, 0)
        .unwrap()
        .expect("mounts fs inside a volume");
    let uri = out.spec.to_uri();
    assert!(uri.contains("volume:") && uri.contains("fs:"), "{uri}");
}

#[test]
fn descends_a_container_into_its_filesystem() {
    // A container whose payload begins at offset 1024 and carries the fs magic.
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .container(FakeContainer {
            magic: b"CONT",
            inner: (1024, 7168),
            tail: false,
        });
    let mut data = b"CONT".to_vec();
    data.resize(1024, 0);
    data.extend_from_slice(b"FSFS");
    data.resize(8192, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let out = reg
        .open(mem(data), base, 0)
        .unwrap()
        .expect("mounts fs inside a container");
    assert!(out.spec.to_uri().contains("fs:"));
}

#[test]
fn a_tail_probed_container_matches_a_trailer_magic() {
    // The container magic sits only in the tail (last bytes of the source), and
    // the fs magic sits at an inner offset the container decodes to. The head has
    // neither, so resolution must read the tail window and match has_magic_from_end
    // inside Openers::open — the DMG-koly-footer path.
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .container(FakeContainer {
            magic: b"KOLY",
            inner: (16, 8192),
            tail: true,
        });
    let mut data = vec![0u8; 16];
    data.extend_from_slice(b"FSFS"); // fs magic at the decoded payload's start
    data.resize(8188, 0);
    data.extend_from_slice(b"KOLY"); // container trailer at the tail
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let out = reg
        .open(mem(data), base, 0)
        .unwrap()
        .expect("tail-probed container decodes to a mountable fs");
    assert!(out.spec.to_uri().contains("fs:"));
}

#[test]
fn unrecognized_source_resolves_to_none() {
    let reg = Openers::new().filesystem(FakeFsProbe {
        magic: b"FSFS",
        fail: false,
    });
    let base = Locator::root(Layer::Range {
        start: 0,
        len: 4096,
    });
    assert!(reg.open(mem(vec![0u8; 4096]), base, 0).unwrap().is_none());
}

#[test]
fn a_volume_system_whose_volumes_hold_no_fs_falls_through_to_none() {
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .volume_system(FakeVsProbe {
            magic: b"VOLS",
            windows: vec![(512, 512)],
        });
    let mut data = b"VOLS".to_vec();
    data.resize(4096, 0); // the partition window is all zeros -> no fs
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    assert!(reg.open(mem(data), base, 0).unwrap().is_none());
}

#[test]
fn a_container_whose_payload_holds_no_fs_falls_through_to_none() {
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .container(FakeContainer {
            magic: b"CONT",
            inner: (16, 4096),
            tail: false,
        });
    let mut data = b"CONT".to_vec();
    data.resize(4096, 0); // payload after offset 16 is all zeros -> no fs
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    assert!(reg.open(mem(data), base, 0).unwrap().is_none());
}

#[test]
fn descends_an_archive_stream_into_its_filesystem() {
    // A bare-wrapper archive (1→1): its Stream peel exposes the fs magic at an
    // inner offset. The locator must carry a bare `Layer::Archive { member: None }`.
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .archive(FakeArchive {
            magic: b"GZIP",
            members: false,
            inner: (16, 8192),
        });
    let mut data = b"GZIP".to_vec();
    data.resize(16, 0);
    data.extend_from_slice(b"FSFS"); // fs magic at the decoded stream's start
    data.resize(16 + 8192, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let out = reg
        .open(mem(data), base, 0)
        .unwrap()
        .expect("mounts fs inside an archive stream");
    let uri = out.spec.to_uri();
    assert!(uri.contains("archive:") && uri.contains("fs:"), "{uri}");
    // The 1→1 peel carries no member index.
    assert!(
        out.spec
            .layers()
            .iter()
            .any(|l| matches!(l, Layer::Archive { member: None })),
        "{uri}"
    );
}

#[test]
fn descends_an_archive_member_into_its_filesystem() {
    // A multi-member archive (1→N): the single member's source exposes the fs
    // magic. The locator must carry `Layer::Archive { member: Some(0) }`.
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .archive(FakeArchive {
            magic: b"ZIPM",
            members: true,
            inner: (16, 8192),
        });
    let mut data = b"ZIPM".to_vec();
    data.resize(16, 0);
    data.extend_from_slice(b"FSFS");
    data.resize(16 + 8192, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let out = reg
        .open(mem(data), base, 0)
        .unwrap()
        .expect("mounts fs inside an archive member");
    let uri = out.spec.to_uri();
    assert!(
        out.spec
            .layers()
            .iter()
            .any(|l| matches!(l, Layer::Archive { member: Some(0) })),
        "{uri}"
    );
}

#[test]
fn an_archive_stream_holding_no_fs_falls_through_to_none() {
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .archive(FakeArchive {
            magic: b"GZIP",
            members: false,
            inner: (16, 4096),
        });
    let mut data = b"GZIP".to_vec();
    data.resize(4096, 0); // decoded stream is all zeros -> no fs
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    assert!(reg.open(mem(data), base, 0).unwrap().is_none());
}

#[test]
fn an_archive_member_holding_no_fs_falls_through_to_none() {
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .archive(FakeArchive {
            magic: b"ZIPM",
            members: true,
            inner: (16, 4096),
        });
    let mut data = b"ZIPM".to_vec();
    data.resize(4096, 0); // the member is all zeros -> no fs
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    assert!(reg.open(mem(data), base, 0).unwrap().is_none());
}

// --- resolve_to_source: raw-source terminal (ADR 0011) -------------------

#[test]
fn resolve_to_source_returns_a_bare_source_as_its_own_terminal() {
    // A raw dump that no packaging (container/archive) prober claims IS the
    // terminal: resolve_to_source hands it straight back, unwrapped.
    let reg = Openers::new();
    let data = b"RAWDUMP0".to_vec();
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let resolved: ResolvedSource = reg
        .resolve_to_source(mem(data), base, 0)
        .unwrap()
        .expect("a bare source is its own raw terminal");
    let mut buf = [0u8; 8];
    let n = resolved.source.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 8);
    assert_eq!(&buf, b"RAWDUMP0");
}

#[test]
fn resolve_to_source_returns_the_innermost_stream_peel_not_none() {
    // A gz-over-raw chain: a bare-wrapper archive peels to a raw memory-dump-like
    // stream that NO filesystem prober claims. The disk `open()` terminal would
    // discard this as `Ok(None)`; `resolve_to_source` must RETURN the peeled inner
    // source (the raw bytes), never drop it.
    let reg = Openers::new().archive(FakeArchive {
        magic: b"GZIP",
        members: false,
        inner: (16, 256),
    });
    let mut data = b"GZIP".to_vec();
    data.resize(16, 0);
    data.extend_from_slice(b"RAWDUMP0"); // inner payload marker at the peel's start
    data.resize(16 + 256, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    // Sanity: the disk terminal drops this non-filesystem source.
    assert!(reg
        .open(mem(data.clone()), base.clone(), 0)
        .unwrap()
        .is_none());
    let resolved = reg
        .resolve_to_source(mem(data), base, 0)
        .unwrap()
        .expect("the peeled stream is returned, not dropped");
    let mut buf = [0u8; 8];
    let n = resolved.source.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 8);
    assert_eq!(
        &buf, b"RAWDUMP0",
        "returned source is the decoded inner stream"
    );
    // The locator records the bare (1→1) archive peel.
    assert!(
        resolved
            .spec
            .layers()
            .iter()
            .any(|l| matches!(l, Layer::Archive { member: None })),
        "{}",
        resolved.spec.to_uri()
    );
}

#[test]
fn resolve_to_source_returns_a_single_member_source() {
    // A multi-member archive (1→N) with a single dump member: resolve_to_source
    // returns that member's source and records `Layer::Archive { member: Some(0) }`.
    let reg = Openers::new().archive(FakeArchive {
        magic: b"ZIPM",
        members: true,
        inner: (16, 256),
    });
    let mut data = b"ZIPM".to_vec();
    data.resize(16, 0);
    data.extend_from_slice(b"RAWDUMP0");
    data.resize(16 + 256, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let resolved = reg
        .resolve_to_source(mem(data), base, 0)
        .unwrap()
        .expect("the member source is returned");
    let mut buf = [0u8; 8];
    resolved.source.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf, b"RAWDUMP0");
    assert!(
        resolved
            .spec
            .layers()
            .iter()
            .any(|l| matches!(l, Layer::Archive { member: Some(0) })),
        "{}",
        resolved.spec.to_uri()
    );
}

#[test]
fn resolve_to_source_peels_a_container_then_archive_nesting() {
    // A container decodes to an inner region that is itself a bare-wrapper archive
    // over the raw dump — proving the shared packaging descent recurses across both
    // layer kinds and stops at the raw bytes (never a filesystem mount).
    let reg = Openers::new()
        .container(FakeContainer {
            magic: b"CONT",
            inner: (32, 512),
            tail: false,
        })
        .archive(FakeArchive {
            magic: b"GZIP",
            members: false,
            inner: (16, 256),
        });
    // [0..32) header w/ CONT magic; container decodes to [32..544):
    //   at 32: GZIP magic; archive Stream decodes to [32+16 .. 32+16+256):
    //     at 48: RAWDUMP0 marker.
    let mut data = b"CONT".to_vec();
    data.resize(32, 0);
    data.extend_from_slice(b"GZIP"); // archive magic at the container payload start
    data.resize(48, 0);
    data.extend_from_slice(b"RAWDUMP0"); // raw marker at the archive stream start
    data.resize(544, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let resolved = reg
        .resolve_to_source(mem(data), base, 0)
        .unwrap()
        .expect("container→archive→raw peels to the raw terminal");
    let mut buf = [0u8; 8];
    resolved.source.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf, b"RAWDUMP0");
    let uri = resolved.spec.to_uri();
    assert!(
        uri.contains("container:") && uri.contains("archive:"),
        "{uri}"
    );
    assert!(
        !resolved
            .spec
            .layers()
            .iter()
            .any(|l| matches!(l, Layer::Fs { .. })),
        "the source terminal never mounts a filesystem: {uri}"
    );
}

#[test]
fn resolve_to_source_is_depth_capped() {
    // Past the bomb-guard depth cap, resolve_to_source yields None rather than
    // recursing without bound — symmetric with the disk `open()` terminal.
    let reg = Openers::new();
    let base = Locator::root(Layer::Range { start: 0, len: 16 });
    assert!(reg
        .resolve_to_source(mem(vec![0u8; 16]), base, 100)
        .unwrap()
        .is_none());
}

// --- encryption descent (ADR 0010) ---------------------------------------

#[test]
fn descends_a_signature_encryption_layer_into_its_filesystem() {
    // A BitLocker-style signature layer: probe says Yes on the head magic, and its
    // decrypt reveals the fs magic at an inner offset. The locator must gain a
    // Layer::Encryption node above the fs: layer.
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .encryption(FakeEncProbe {
            scheme: EncryptionScheme::Bitlocker,
            verdict: FakeVerdict::Signature(b"BDE!"),
            inner: Some((512, 8192)),
            attempts: Arc::new(Mutex::new(0)),
        });
    let mut data = b"BDE!".to_vec();
    data.resize(512, 0);
    data.extend_from_slice(b"FSFS"); // fs magic at the decrypted volume's start
    data.resize(512 + 8192, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let out = reg
        .open_with_credentials(mem(data), base, 0, &NoCredentials)
        .unwrap()
        .expect("mounts fs behind a signature encryption layer");
    let uri = out.spec.to_uri();
    assert!(
        uri.contains("encryption:bitlocker") && uri.contains("fs:"),
        "{uri}"
    );
    assert!(
        out.spec.layers().iter().any(|l| matches!(
            l,
            Layer::Encryption {
                scheme: EncryptionScheme::Bitlocker
            }
        )),
        "{uri}"
    );
}

#[test]
fn a_signature_encryption_whose_decrypt_fails_propagates_loud() {
    // A positive (Yes) verdict is an identification: a failed decrypt (wrong/absent
    // key) must fail loud, never masquerade as a clean unknown None.
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .encryption(FakeEncProbe {
            scheme: EncryptionScheme::Luks1,
            verdict: FakeVerdict::Signature(b"LUKS"),
            inner: None, // decrypt errors
            attempts: Arc::new(Mutex::new(0)),
        });
    let mut data = b"LUKS".to_vec();
    data.resize(8192, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    assert!(reg
        .open_with_credentials(mem(data), base, 0, &NoCredentials)
        .is_err());
}

#[test]
fn a_credential_attempt_scheme_never_shadows_a_real_filesystem() {
    // A VeraCrypt-style Maybe scheme must be a LAST RESORT: a plaintext filesystem
    // at the top claims the source first, so the credential-attempt decrypt is
    // never even driven (attempts stays 0) and no encryption layer is recorded.
    let attempts = Arc::new(Mutex::new(0usize));
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .encryption(FakeEncProbe {
            scheme: EncryptionScheme::VeraCrypt,
            verdict: FakeVerdict::CredentialAttempt,
            inner: Some((0, 8192)), // would "succeed" if it were ever attempted
            attempts: attempts.clone(),
        });
    let mut data = b"FSFS".to_vec();
    data.resize(8192, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let out = reg
        .open_with_credentials(mem(data), base, 0, &NoCredentials)
        .unwrap()
        .expect("plaintext fs mounts directly");
    assert_eq!(
        *attempts.lock().unwrap(),
        0,
        "a credential-attempt scheme must not be tried while a real fs claims the source"
    );
    assert!(
        !out.spec
            .layers()
            .iter()
            .any(|l| matches!(l, Layer::Encryption { .. })),
        "no encryption layer belongs in a plaintext stack"
    );
}

#[test]
fn a_credential_attempt_scheme_descends_as_a_last_resort() {
    // Nothing else recognizes the source; the Maybe scheme is attempted last, its
    // decrypt reveals an fs, and the stack records Layer::Encryption{VeraCrypt}.
    let attempts = Arc::new(Mutex::new(0usize));
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .encryption(FakeEncProbe {
            scheme: EncryptionScheme::VeraCrypt,
            verdict: FakeVerdict::CredentialAttempt,
            inner: Some((512, 8192)),
            attempts: attempts.clone(),
        });
    // The head carries no fs/container/volume magic; only the decrypted view does.
    let mut data = vec![0u8; 512];
    data.extend_from_slice(b"FSFS");
    data.resize(512 + 8192, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let out = reg
        .open_with_credentials(mem(data), base, 0, &NoCredentials)
        .unwrap()
        .expect("veracrypt decrypts to a mountable fs");
    assert_eq!(
        *attempts.lock().unwrap(),
        1,
        "the last-resort decrypt ran once"
    );
    assert!(
        out.spec.layers().iter().any(|l| matches!(
            l,
            Layer::Encryption {
                scheme: EncryptionScheme::VeraCrypt
            }
        )),
        "{}",
        out.spec.to_uri()
    );
}

#[test]
fn a_credential_attempt_whose_decrypt_fails_falls_through_to_none() {
    // A failed Maybe decrypt (not this scheme / wrong creds) is indistinguishable
    // from random data: it must fall through to None, never break the empty-source
    // contract by erroring on every unrecognized blob.
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .encryption(FakeEncProbe {
            scheme: EncryptionScheme::VeraCrypt,
            verdict: FakeVerdict::CredentialAttempt,
            inner: None, // decrypt fails
            attempts: Arc::new(Mutex::new(0)),
        });
    let base = Locator::root(Layer::Range {
        start: 0,
        len: 4096,
    });
    assert!(reg
        .open_with_credentials(mem(vec![0u8; 4096]), base, 0, &NoCredentials)
        .unwrap()
        .is_none());
}

#[test]
fn a_signature_scheme_that_does_not_match_yields_a_no_verdict() {
    // A registered signature scheme whose magic is absent returns Confidence::No and
    // is simply skipped — the source resolves to None with no encryption layer.
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .encryption(FakeEncProbe {
            scheme: EncryptionScheme::Bitlocker,
            verdict: FakeVerdict::Signature(b"BDE!"),
            inner: Some((0, 4096)),
            attempts: Arc::new(Mutex::new(0)),
        });
    let base = Locator::root(Layer::Range {
        start: 0,
        len: 4096,
    });
    // All-zero source: no fs magic, no BDE! magic -> No verdict -> None.
    assert!(reg
        .open_with_credentials(mem(vec![0u8; 4096]), base, 0, &NoCredentials)
        .unwrap()
        .is_none());
}

#[test]
fn a_signature_scheme_whose_plaintext_holds_no_fs_falls_through_to_none() {
    // A Yes signature decrypts successfully, but the plaintext carries no fs magic:
    // the nested resolve returns None and the descent falls through to None (the
    // decrypt itself did not fail, so this is not the loud-propagation path).
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .encryption(FakeEncProbe {
            scheme: EncryptionScheme::Bitlocker,
            verdict: FakeVerdict::Signature(b"BDE!"),
            inner: Some((512, 4096)), // decrypted window is all zeros -> no fs
            attempts: Arc::new(Mutex::new(0)),
        });
    let mut data = b"BDE!".to_vec();
    data.resize(512 + 4096, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    assert!(reg
        .open_with_credentials(mem(data), base, 0, &NoCredentials)
        .unwrap()
        .is_none());
}

#[test]
fn a_credential_attempt_whose_plaintext_holds_no_fs_falls_through_to_none() {
    // The last-resort decrypt succeeds but the plaintext carries no fs magic: the
    // nested resolve returns None and the loop falls through to None.
    let attempts = Arc::new(Mutex::new(0usize));
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .encryption(FakeEncProbe {
            scheme: EncryptionScheme::VeraCrypt,
            verdict: FakeVerdict::CredentialAttempt,
            inner: Some((0, 4096)), // decrypted window is all zeros -> no fs
            attempts: attempts.clone(),
        });
    let base = Locator::root(Layer::Range {
        start: 0,
        len: 4096,
    });
    assert!(reg
        .open_with_credentials(mem(vec![0u8; 4096]), base, 0, &NoCredentials)
        .unwrap()
        .is_none());
    // A self-referential credential-attempt decrypt is bounded by the same depth
    // cap that guards a container loop.
    assert!(
        *attempts.lock().unwrap() >= 1,
        "the last-resort decrypt was driven"
    );
}

#[test]
fn plain_open_delegates_through_no_credentials_and_still_descends_encryption() {
    // The retained no-credential `open` entry point delegates to
    // open_with_credentials(&NoCredentials): a signature layer still descends.
    let reg = Openers::new()
        .filesystem(FakeFsProbe {
            magic: b"FSFS",
            fail: false,
        })
        .encryption(FakeEncProbe {
            scheme: EncryptionScheme::FileVault,
            verdict: FakeVerdict::Signature(b"CS!!"),
            inner: Some((16, 8192)),
            attempts: Arc::new(Mutex::new(0)),
        });
    let mut data = b"CS!!".to_vec();
    data.resize(16, 0);
    data.extend_from_slice(b"FSFS");
    data.resize(16 + 8192, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    let out = reg
        .open(mem(data), base, 0)
        .unwrap()
        .expect("descends encryption via the retained open()");
    assert!(
        out.spec.layers().iter().any(|l| matches!(
            l,
            Layer::Encryption {
                scheme: EncryptionScheme::FileVault
            }
        )),
        "{}",
        out.spec.to_uri()
    );
}

#[test]
fn recursion_is_depth_capped_on_a_self_referential_container() {
    // A container that decodes to its own whole self recurses forever; the depth
    // cap breaks it, yielding None rather than a stack overflow.
    let reg = Openers::new().container(FakeContainer {
        magic: b"LOOP",
        inner: (0, 4096),
        tail: false,
    });
    let mut data = b"LOOP".to_vec();
    data.resize(4096, 0);
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    assert!(reg.open(mem(data), base, 0).unwrap().is_none());
}

#[test]
fn an_empty_source_reads_a_single_byte_window_and_resolves_to_none() {
    // total == 0 exercises the clamp(1, ..) head window and the zero-length tail.
    let reg = Openers::new().filesystem(FakeFsProbe {
        magic: b"FSFS",
        fail: false,
    });
    let base = Locator::root(Layer::Range { start: 0, len: 0 });
    assert!(reg.open(mem(Vec::new()), base, 0).unwrap().is_none());
}

// --- walk ----------------------------------------------------------------

fn fs_with(tree: Tree) -> TreeFs {
    TreeFs { tree }
}

#[test]
fn walk_enumerates_the_tree_and_skips_dot_entries() {
    let fs = fs_with(vec![
        (
            0,
            vec![
                (b".".to_vec(), 0, NodeKind::Dir),
                (b"..".to_vec(), 0, NodeKind::Dir),
                (b"dir".to_vec(), 1, NodeKind::Dir),
                (b"a.txt".to_vec(), 2, NodeKind::File),
            ],
        ),
        (1, vec![(b"b.txt".to_vec(), 3, NodeKind::File)]),
    ]);
    let entries = walk(&fs).unwrap();
    let names: Vec<String> = entries
        .iter()
        .filter_map(|e| {
            e.path
                .last()
                .map(|n| String::from_utf8_lossy(n).to_string())
        })
        .collect();
    assert!(names.contains(&"dir".to_string()));
    assert!(names.contains(&"a.txt".to_string()));
    assert!(names.contains(&"b.txt".to_string()));
    assert!(!names.iter().any(|n| n == "." || n == ".."));
    // b.txt is nested one level under dir.
    let b = entries
        .iter()
        .find(|e| e.path.last().map(Vec::as_slice) == Some(b"b.txt".as_slice()))
        .unwrap();
    assert_eq!(b.path.len(), 2);
}

#[test]
fn walk_is_loop_guarded_against_a_self_referential_directory() {
    // A directory that lists itself as a child would recurse forever without the
    // visited set; walk terminates.
    let fs = fs_with(vec![(0, vec![(b"self".to_vec(), 0, NodeKind::Dir)])]);
    let entries = walk(&fs).unwrap();
    // The single "self" entry is emitted once; the loop back into id 0 is guarded.
    assert_eq!(entries.len(), 1);
}

#[test]
fn walk_propagates_a_read_dir_error() {
    struct Boom;
    impl FileSystem for Boom {
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
        fn read_dir(&self, _ino: FileId) -> VfsResult<DirStream> {
            Err(VfsError::Decode {
                layer: "boom",
                offset: 0,
                detail: "read_dir failed".to_string(),
                bytes: forensic_vfs::SmallHex::new(&[]),
            })
        }
        fn extents(
            &self,
            _ino: FileId,
            _stream: forensic_vfs::StreamId,
        ) -> VfsResult<forensic_vfs::ExtentStream> {
            Ok(forensic_vfs::ExtentStream::empty())
        }
        fn lookup(&self, _parent: FileId, _name: &[u8]) -> VfsResult<Option<FileId>> {
            Ok(None)
        }
        fn meta(&self, _ino: FileId) -> VfsResult<FsMeta> {
            Err(VfsError::Decode {
                layer: "boom",
                offset: 0,
                detail: "meta failed".to_string(),
                bytes: forensic_vfs::SmallHex::new(&[]),
            })
        }
        fn read_at(
            &self,
            _ino: FileId,
            _stream: forensic_vfs::StreamId,
            _off: u64,
            _buf: &mut [u8],
        ) -> VfsResult<usize> {
            Ok(0)
        }
        fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
            Ok(Vec::new())
        }
        fn deleted(&self) -> VfsResult<forensic_vfs::NodeStream> {
            Ok(forensic_vfs::NodeStream::empty())
        }
        fn unallocated(&self) -> VfsResult<forensic_vfs::ExtentStream> {
            Ok(forensic_vfs::ExtentStream::empty())
        }
    }
    assert!(walk(&Boom).is_err());
}

#[test]
fn walk_propagates_a_meta_error() {
    // read_dir yields one entry but meta on it fails -> walk aborts loud.
    struct MetaBoom;
    impl FileSystem for MetaBoom {
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
        fn read_dir(&self, _ino: FileId) -> VfsResult<DirStream> {
            Ok(DirStream::new(std::iter::once(Ok(DirEntry {
                name: b"x".to_vec(),
                id: FileId::Opaque(1),
                kind: NodeKind::File,
            }))))
        }
        fn extents(
            &self,
            _ino: FileId,
            _stream: forensic_vfs::StreamId,
        ) -> VfsResult<forensic_vfs::ExtentStream> {
            Ok(forensic_vfs::ExtentStream::empty())
        }
        fn lookup(&self, _parent: FileId, _name: &[u8]) -> VfsResult<Option<FileId>> {
            Ok(None)
        }
        fn meta(&self, _ino: FileId) -> VfsResult<FsMeta> {
            Err(VfsError::Decode {
                layer: "boom",
                offset: 0,
                detail: "meta failed".to_string(),
                bytes: forensic_vfs::SmallHex::new(&[]),
            })
        }
        fn read_at(
            &self,
            _ino: FileId,
            _stream: forensic_vfs::StreamId,
            _off: u64,
            _buf: &mut [u8],
        ) -> VfsResult<usize> {
            Ok(0)
        }
        fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
            Ok(Vec::new())
        }
        fn deleted(&self) -> VfsResult<forensic_vfs::NodeStream> {
            Ok(forensic_vfs::NodeStream::empty())
        }
        fn unallocated(&self) -> VfsResult<forensic_vfs::ExtentStream> {
            Ok(forensic_vfs::ExtentStream::empty())
        }
    }
    assert!(walk(&MetaBoom).is_err());
}

#[test]
fn walk_propagates_a_dir_entry_stream_error() {
    // The dir stream itself yields an Err item -> walk aborts loud.
    struct EntryBoom;
    impl FileSystem for EntryBoom {
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
        fn read_dir(&self, _ino: FileId) -> VfsResult<DirStream> {
            Ok(DirStream::new(std::iter::once(Err(VfsError::Decode {
                layer: "boom",
                offset: 0,
                detail: "entry failed".to_string(),
                bytes: forensic_vfs::SmallHex::new(&[]),
            }))))
        }
        fn extents(
            &self,
            _ino: FileId,
            _stream: forensic_vfs::StreamId,
        ) -> VfsResult<forensic_vfs::ExtentStream> {
            Ok(forensic_vfs::ExtentStream::empty())
        }
        fn lookup(&self, _parent: FileId, _name: &[u8]) -> VfsResult<Option<FileId>> {
            Ok(None)
        }
        fn meta(&self, _ino: FileId) -> VfsResult<FsMeta> {
            Err(VfsError::Decode {
                layer: "boom",
                offset: 0,
                detail: "meta".to_string(),
                bytes: forensic_vfs::SmallHex::new(&[]),
            })
        }
        fn read_at(
            &self,
            _ino: FileId,
            _stream: forensic_vfs::StreamId,
            _off: u64,
            _buf: &mut [u8],
        ) -> VfsResult<usize> {
            Ok(0)
        }
        fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
            Ok(Vec::new())
        }
        fn deleted(&self) -> VfsResult<forensic_vfs::NodeStream> {
            Ok(forensic_vfs::NodeStream::empty())
        }
        fn unallocated(&self) -> VfsResult<forensic_vfs::ExtentStream> {
            Ok(forensic_vfs::ExtentStream::empty())
        }
    }
    assert!(walk(&EntryBoom).is_err());
}

#[test]
fn walk_is_depth_capped() {
    // A linear chain deeper than WALK_MAX_DEPTH terminates without unbounded
    // recursion: each id N is a dir whose only child is id N+1.
    let depth = 300u64;
    let tree: Tree = (0..depth)
        .map(|n| {
            (
                n,
                vec![(format!("d{n}").into_bytes(), n + 1, NodeKind::Dir)],
            )
        })
        .collect();
    // walk must terminate (the depth cap stops descent); it returns Ok.
    assert!(walk(&fs_with(tree)).is_ok());
}

// --- Evidence + SnapshotView helpers -------------------------------------

#[test]
fn evidence_carries_a_root_locator_and_optional_fs() {
    let ev = Evidence {
        root: Locator::file("/img.raw"),
        fs: None,
    };
    assert!(ev.fs.is_none());
    assert_eq!(ev.root, Locator::file("/img.raw"));
}

#[test]
fn epoch_from_create_time_round_trips_and_orders() {
    let t = 0x0123_4567_89ab_cdefu64;
    let tag = epoch_from_create_time(t);
    assert_eq!(&tag.0[0..24], &[0u8; 24], "high 24 bytes are zero");
    assert_eq!(
        u64::from_be_bytes(tag.0[24..32].try_into().unwrap()),
        t,
        "create_time round-trips out of the low 8 bytes"
    );
    assert!(
        epoch_from_create_time(t + 1).0 > tag.0,
        "a later create_time yields a greater tag"
    );
}

#[test]
fn snapshot_view_carries_epoch_and_snapshot_locator() {
    let base = Locator::file("/ev.dmg");
    let v = snapshot_view(&base, 42, "daily".to_string(), 1000);
    assert_eq!(v.xid, 42);
    assert_eq!(v.name, "daily");
    assert_eq!(v.epoch, epoch_from_create_time(1000));
    assert!(matches!(
        v.locator.layer,
        Layer::Snapshot {
            store: SnapshotRef::ApfsXid(42)
        }
    ));
}

// A shared-state sanity check that the resolver's source-cloning keeps the base
// alive across the recursive descent (an Arc clone, not a move).
#[test]
fn resolve_keeps_the_base_source_shared_across_layers() {
    struct Counting {
        inner: DynSource,
        seen: Arc<Mutex<usize>>,
    }
    impl ImageSource for Counting {
        fn len(&self) -> u64 {
            self.inner.len()
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
            *self.seen.lock().unwrap() += 1;
            self.inner.read_at(offset, buf)
        }
    }
    let seen = Arc::new(Mutex::new(0usize));
    let reg = Openers::new().filesystem(FakeFsProbe {
        magic: b"FSFS",
        fail: false,
    });
    let mut data = b"FSFS".to_vec();
    data.resize(8192, 0);
    let src: DynSource = Arc::new(Counting {
        inner: mem(data.clone()),
        seen: seen.clone(),
    });
    let base = Locator::root(Layer::Range {
        start: 0,
        len: data.len() as u64,
    });
    assert!(reg.open(src, base, 0).unwrap().is_some());
    assert!(*seen.lock().unwrap() >= 1, "the base source was read");
}

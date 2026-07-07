//! # forensic-vfs-engine
//!
//! The registry + resolver over the `forensic-vfs` contracts: one
//! [`Vfs::open`] that detects the container/volume/filesystem stack of a piece
//! of evidence and mounts a read-only `dyn FileSystem`. This is the
//! ORCHESTRATION crate — the one place that depends *down* on every fleet reader.

use std::path::Path;
use std::sync::Arc;

use forensic_vfs::adapters::{FileSource, SourceCursor, SubRange};
use forensic_vfs::read::{le_u32, le_u64};
use forensic_vfs::{
    Confidence, DynFs, DynSource, FileSystemProbe, FsKind, PathSpec, Registry, SmallHex,
    SniffWindow, VfsError, VfsResult, VolumeDesc, VolumeKind, VolumeScheme, VolumeSystem,
    VolumeSystemProbe,
};

/// Depth cap on the recursive resolve (container/volume nesting) — a bomb guard.
const MAX_DEPTH: usize = 8;

/// One resolved piece of evidence: its locator plus the mounted filesystem, when
/// the engine detected one (`None` for a source no registered prober recognized).
pub struct Evidence {
    /// The locator this evidence was opened from.
    pub root: PathSpec,
    /// The mounted read-only filesystem, if detected.
    pub fs: Option<DynFs>,
}

/// The engine handle: the reader registry plus the resolver.
pub struct Vfs {
    registry: Registry,
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs {
    /// A `Vfs` with every fleet reader registered ([`default_registry`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: default_registry(),
        }
    }

    /// Open evidence at `path`: resolve the base byte source (an EWF container by
    /// path, or a raw file), then recurse container/volume/filesystem layers and
    /// mount the first filesystem found. A source nothing recognizes yields an
    /// `Evidence` with `fs: None` — a genuinely clean unknown, not an error.
    pub fn open(&self, path: &Path) -> VfsResult<Evidence> {
        let base = open_base(path)?;
        let fs = self.resolve(base, 0)?;
        Ok(Evidence {
            root: PathSpec::os(path),
            fs,
        })
    }

    /// Recursively resolve a source to a filesystem: sniff its head; if a
    /// filesystem prober recognizes it, mount it; otherwise if a volume-system
    /// prober recognizes it, descend into each volume and resolve that.
    fn resolve(&self, source: DynSource, depth: usize) -> VfsResult<Option<DynFs>> {
        if depth > MAX_DEPTH {
            return Ok(None);
        }
        let mut head = [0u8; 4096];
        let n = source.read_at(0, &mut head)?;
        let window = SniffWindow::new(0, head.get(..n).unwrap_or(&[]));

        for probe in self.registry.filesystems() {
            if probe.probe(&window).is_candidate() {
                return Ok(Some(probe.open(source.clone())?));
            }
        }
        for vsp in self.registry.volume_systems() {
            if vsp.probe(&window).is_candidate() {
                let vs = vsp.open(source.clone())?;
                for index in 0..vs.volumes().len() {
                    let sub = vs.open_volume(index)?;
                    if let Some(fs) = self.resolve(sub, depth + 1)? {
                        return Ok(Some(fs));
                    }
                }
            }
        }
        Ok(None)
    }
}

/// The fleet reader registry: filesystem probers + volume-system probers.
/// Container decoders and crypto layers register here as those readers grow
/// their `vfs` features.
#[must_use]
pub fn default_registry() -> Registry {
    Registry::new()
        .filesystem(NtfsProbe)
        .volume_system(GptProbe)
        .volume_system(MbrProbe)
}

/// Resolve the base [`DynSource`] for a path. EWF is multi-segment and opens *by
/// path* (it discovers `.E02...` itself), so it is handled here rather than as a
/// single-stream `ContainerDecoder`; everything else is a raw [`FileSource`].
fn open_base(path: &Path) -> VfsResult<DynSource> {
    if is_ewf(path) {
        let reader = ewf::EwfReader::open(path).map_err(|e| VfsError::Bootstrap {
            stage: "ewf::open",
            detail: e.to_string(),
        })?;
        Ok(Arc::new(reader))
    } else {
        Ok(Arc::new(FileSource::open(path)?))
    }
}

fn is_ewf(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("e01") || e.eq_ignore_ascii_case("ex01"))
}

/// NTFS filesystem prober: recognizes the `NTFS` OEM id and mounts `ntfs_core::NtfsFs`.
struct NtfsProbe;

impl FileSystemProbe for NtfsProbe {
    fn kind(&self) -> FsKind {
        FsKind::Ntfs
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // NTFS boot sector: OEM id "NTFS    " at byte offset 3.
        if w.has_magic(3, b"NTFS    ") {
            Confidence::Yes { how: "NTFS OEM id" }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynFs> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let fs = ntfs_core::NtfsFs::open(cursor).map_err(|e| VfsError::Decode {
            layer: "ntfs",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })?;
        Ok(Arc::new(fs))
    }
}

/// MBR (DOS) partition-table volume system: the classic 4-entry table at the end
/// of the boot sector. Extended partitions (types 0x05/0x0f) are not yet chased.
struct MbrProbe;

impl VolumeSystemProbe for MbrProbe {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Mbr
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // 0x55AA boot signature plus at least one plausible partition entry.
        if w.at(510, 2) != Some(&[0x55, 0xaa]) {
            return Confidence::No;
        }
        let data = w.bytes();
        for i in 0..4usize {
            let base = 446 + i * 16;
            let ptype = data.get(base + 4).copied().unwrap_or(0);
            let size = le_u32(data, base + 12);
            if ptype != 0 && ptype != 0xEE && size != 0 {
                return Confidence::Yes {
                    how: "MBR partition table",
                };
            }
        }
        Confidence::No
    }

    fn open(&self, src: DynSource) -> VfsResult<Box<dyn VolumeSystem>> {
        Ok(Box::new(Mbr::parse(src)?))
    }
}

/// A parsed MBR: the parent source plus its primary partitions.
struct Mbr {
    parent: DynSource,
    volumes: Vec<VolumeDesc>,
}

impl Mbr {
    fn parse(src: DynSource) -> VfsResult<Self> {
        let mut sector = [0u8; 512];
        src.read_at(0, &mut sector)?;
        let mut volumes = Vec::new();
        for i in 0..4usize {
            let base = 446 + i * 16;
            let ptype = sector.get(base + 4).copied().unwrap_or(0);
            let start_lba = le_u32(&sector, base + 8);
            let size = le_u32(&sector, base + 12);
            if ptype == 0 || ptype == 0xEE || size == 0 {
                continue;
            }
            volumes.push(VolumeDesc {
                index: i,
                kind: VolumeKind::Partition,
                start: u64::from(start_lba) * 512,
                len: u64::from(size) * 512,
                type_hint: Some(format!("0x{ptype:02x}")),
                label: None,
            });
        }
        Ok(Self {
            parent: src,
            volumes,
        })
    }
}

impl VolumeSystem for Mbr {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Mbr
    }

    fn volumes(&self) -> &[VolumeDesc] {
        &self.volumes
    }

    fn open_volume(&self, index: usize) -> VfsResult<DynSource> {
        let desc = self.volumes.get(index).ok_or(VfsError::OutOfRange {
            what: "mbr volume index",
            offset: index as u64,
            len: 1,
            bound: self.volumes.len() as u64,
        })?;
        Ok(Arc::new(SubRange::new(
            self.parent.clone(),
            desc.start,
            desc.len,
        )))
    }
}

/// GPT (GUID Partition Table) volume system: the `EFI PART` header at LBA 1 and
/// its partition-entry array. The protective MBR at LBA 0 is left to `MbrProbe`,
/// which ignores the 0xEE marker so GPT takes over.
struct GptProbe;

impl VolumeSystemProbe for GptProbe {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Gpt
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // GPT header signature "EFI PART" at LBA 1 (byte offset 512).
        if w.has_magic(512, b"EFI PART") {
            Confidence::Yes {
                how: "GPT EFI PART header",
            }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<Box<dyn VolumeSystem>> {
        Ok(Box::new(Gpt::parse(src)?))
    }
}

/// A parsed GPT: the parent source plus its partitions.
struct Gpt {
    parent: DynSource,
    volumes: Vec<VolumeDesc>,
}

impl Gpt {
    fn parse(src: DynSource) -> VfsResult<Self> {
        // The GPT primary header lives in LBA 1.
        let mut header = [0u8; 512];
        src.read_at(512, &mut header)?;
        if header.get(0..8) != Some(b"EFI PART".as_slice()) {
            return Err(VfsError::Decode {
                layer: "gpt",
                offset: 512,
                detail: "missing EFI PART signature".to_string(),
                bytes: SmallHex::new(header.get(0..8).unwrap_or(&[])),
            });
        }
        let entries_lba = le_u64(&header, 72);
        // Bomb guards: cap the entry count and size before allocating.
        let num_entries = le_u32(&header, 80).min(256) as usize;
        let entry_size = le_u32(&header, 84).clamp(128, 512) as usize;
        let array_len = num_entries.checked_mul(entry_size).unwrap_or(0);
        let mut arr = vec![0u8; array_len];
        src.read_at(entries_lba.saturating_mul(512), &mut arr)?;

        let mut volumes = Vec::new();
        for i in 0..num_entries {
            let Some(base) = i.checked_mul(entry_size) else {
                break;
            };
            let Some(entry) = arr.get(base..base.saturating_add(entry_size)) else {
                break;
            };
            // An all-zero type GUID marks an unused entry.
            let type_guid = entry.get(0..16).unwrap_or(&[]);
            if type_guid.iter().all(|&b| b == 0) {
                continue;
            }
            let first = le_u64(entry, 32);
            let last = le_u64(entry, 40);
            if last < first {
                continue;
            }
            let sectors = last - first + 1;
            volumes.push(VolumeDesc {
                index: i,
                kind: VolumeKind::Partition,
                start: first.saturating_mul(512),
                len: sectors.saturating_mul(512),
                type_hint: Some(guid_hint(type_guid)),
                label: None,
            });
        }
        Ok(Self {
            parent: src,
            volumes,
        })
    }
}

impl VolumeSystem for Gpt {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Gpt
    }

    fn volumes(&self) -> &[VolumeDesc] {
        &self.volumes
    }

    fn open_volume(&self, index: usize) -> VfsResult<DynSource> {
        let desc = self.volumes.get(index).ok_or(VfsError::OutOfRange {
            what: "gpt volume index",
            offset: index as u64,
            len: 1,
            bound: self.volumes.len() as u64,
        })?;
        Ok(Arc::new(SubRange::new(
            self.parent.clone(),
            desc.start,
            desc.len,
        )))
    }
}

fn guid_hint(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

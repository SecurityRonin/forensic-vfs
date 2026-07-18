//! # forensic-vfs-resolver
//!
//! The generic layer resolver: sniff a byte source, match a registered prober,
//! and descend container/volume/filesystem layers until a filesystem mounts.
//!
//! This is the reader-independent core of detection — it touches only the
//! [`forensic_vfs::Openers`] prober traits and the layered
//! [`PathSpec`]/[`Layer`] model, never a concrete reader. It is deliberately
//! split out of the [`forensic-vfs`](https://docs.rs/forensic-vfs) contract leaf
//! so the *evolving detection behavior* (this crate) is firewalled from the
//! *frozen contract* the fleet's reader crates pin.
//!
//! The orchestration layer (`forensic-vfs-engine`) wires concrete probers into a
//! [`Openers`], resolves a base [`DynSource`] from a path (EWF-by-path vs a raw
//! file), and offers the by-path `open`/snapshot API; everything below that — the
//! recursion, the sniff windows, [`walk`], and the snapshot *view* — lives here so
//! any tool or test can drive it openers-first.
//!
//! Because `open` cannot be an inherent method on the leaf's [`Openers`] from
//! another crate (the orphan rule), it is exposed as the [`SourceOpen`] extension
//! trait; bring it into scope and call `openers.open(source, spec, 0)`.

// Tests may unwrap/expect freely; production code may not.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashSet;

use state_history_forensic::epoch::EpochTag;

use forensic_vfs::{
    DynSource, FileId, FileSystem, FsMeta, Layer, NodeAddr, NodeKind, Openers, PathSpec,
    SnapshotRef, SniffWindow, VfsResult,
};

/// Depth cap on the recursive resolve (container/volume nesting) — a bomb guard.
const MAX_DEPTH: usize = 8;

/// Bytes read into the sniff window. Sized so a prober can see multi-offset
/// magics — notably the ISO 9660 Primary Volume Descriptor (`CD001` at byte
/// offset 32769, LBA 16). NTFS/ext4/MBR/GPT/container magics all sit in the
/// first few KiB, so the larger window is a strict superset. One bounded read.
const SNIFF_CAP: u64 = 40 * 1024;

/// Bytes read into the *tail* sniff window from the end of the source. Sized to
/// cover trailer signatures like the DMG `koly` footer (at `total_len - 512`).
const TAIL_CAP: u64 = 4096;

/// Cap on directory recursion depth in [`walk`] — a filesystem-loop guard.
const WALK_MAX_DEPTH: usize = 256;

/// One resolved piece of evidence: its locator plus the mounted filesystem, when
/// the resolver detected one (`None` for a source no registered prober recognized).
pub struct Evidence {
    /// The locator this evidence was opened from.
    pub root: PathSpec,
    /// The mounted read-only filesystem, if detected.
    pub fs: Option<forensic_vfs::DynFs>,
}

/// One resolved layer stack: the mounted filesystem, its locator, and the byte
/// source it was mounted from (plus that source's pre-filesystem locator, the
/// base a snapshot layer is pushed onto).
pub struct Resolved {
    /// The mounted read-only filesystem.
    pub fs: forensic_vfs::DynFs,
    /// The full locator, topped by the `fs:` layer.
    pub spec: PathSpec,
    /// The byte source the filesystem was mounted from.
    pub source: DynSource,
    /// That source's pre-filesystem locator (the base a snapshot layer sits on).
    pub source_spec: PathSpec,
}

/// The generic layer resolver, exposed as an extension trait on the leaf's
/// [`Openers`]. Bring it into scope (`use forensic_vfs_resolver::SourceOpen;`) to
/// call `openers.open(source, spec, 0)`.
pub trait SourceOpen {
    /// Recursively resolve a source to a filesystem: sniff its head (and a tail
    /// window for trailer magics); if a filesystem prober recognizes it, mount it;
    /// otherwise if a volume-system prober recognizes it, descend into each volume
    /// and resolve that; otherwise if a container decoder recognizes it, decode and
    /// resolve the decoded stream. `Ok(None)` when nothing recognizes it — a
    /// genuinely clean unknown, not an error. A prober's `open` failure after a
    /// positive verdict propagates loud (never a silent `None`).
    ///
    /// `depth` is the current nesting level; callers start at `0`. The recursion is
    /// depth-capped against a self-referential container/volume bomb.
    ///
    /// # Errors
    /// Propagates a source read error, or a prober `open`/decode failure raised
    /// after a positive probe verdict.
    fn open(&self, source: DynSource, spec: PathSpec, depth: usize) -> VfsResult<Option<Resolved>>;
}

impl SourceOpen for Openers {
    fn open(&self, source: DynSource, spec: PathSpec, depth: usize) -> VfsResult<Option<Resolved>> {
        if depth > MAX_DEPTH {
            return Ok(None);
        }
        let total = source.len();
        let cap = total.clamp(1, SNIFF_CAP) as usize;
        let mut head = vec![0u8; cap];
        let n = source.read_at(0, &mut head)?;
        // A tail window (the last bytes of the source) so a prober can match a
        // trailer signature the head never reaches — e.g. the DMG koly footer.
        let tail_cap = total.min(TAIL_CAP);
        let tail_start = total - tail_cap;
        let mut tail = vec![0u8; tail_cap as usize];
        let tn = source.read_at(tail_start, &mut tail)?;
        let window = SniffWindow::with_tail(
            0,
            head.get(..n).unwrap_or(&[]),
            total,
            tail.get(..tn).unwrap_or(&[]),
        );

        for probe in self.filesystems() {
            if probe.probe(&window).is_candidate() {
                let fs = probe.open(source.clone())?;
                let fs_spec = spec.clone().push(Layer::Fs {
                    kind: probe.kind(),
                    at: NodeAddr::Path(Vec::new()),
                });
                return Ok(Some(Resolved {
                    fs,
                    spec: fs_spec,
                    source,
                    source_spec: spec,
                }));
            }
        }
        for vsp in self.volume_systems() {
            if vsp.probe(&window).is_candidate() {
                let vs = vsp.open(source.clone())?;
                for index in 0..vs.volumes().len() {
                    let sub = vs.open_volume(index)?;
                    let child = spec.clone().push(Layer::Volume {
                        scheme: vsp.scheme(),
                        index,
                        guid: None,
                    });
                    if let Some(found) = self.open(sub, child, depth + 1)? {
                        return Ok(Some(found));
                    }
                }
            }
        }
        for cd in self.containers() {
            if cd.probe(&window).is_candidate() {
                let decoded = cd.open(source.clone())?;
                let child = spec.clone().push(Layer::Container {
                    format: cd.format(),
                });
                if let Some(found) = self.open(decoded, child, depth + 1)? {
                    return Ok(Some(found));
                }
            }
        }
        Ok(None)
    }
}

/// One snapshot of a filesystem, viewed as a time-indexed state in the `[H]`
/// cohort: the wall-clock [`EpochTag`], the transaction id, the snapshot name,
/// and a re-openable [`PathSpec`] locator (base ⇒ `Snapshot{ApfsXid}`).
#[derive(Debug, Clone)]
pub struct SnapshotView {
    /// Time-indexed identity, derived from the snapshot's `create_time`.
    pub epoch: EpochTag,
    /// The snapshot transaction id.
    pub xid: u64,
    /// The snapshot name.
    pub name: String,
    /// A locator that the orchestration layer re-opens end-to-end.
    pub locator: PathSpec,
}

/// Build a [`SnapshotView`] under `source_spec` (the source's pre-filesystem
/// locator) from a snapshot's transaction id, name, and `create_time`. Takes
/// primitives rather than a concrete reader's `#[non_exhaustive]` snapshot type so
/// the mapping is unit-testable directly.
#[must_use]
pub fn snapshot_view(
    source_spec: &PathSpec,
    xid: u64,
    name: String,
    create_time: u64,
) -> SnapshotView {
    SnapshotView {
        epoch: epoch_from_create_time(create_time),
        xid,
        name,
        locator: source_spec.clone().push(Layer::Snapshot {
            store: SnapshotRef::ApfsXid(xid),
        }),
    }
}

/// Derive an [`EpochTag`] from a snapshot `create_time` (nanoseconds since
/// 1970-01-01 UTC). The big-endian nanosecond timestamp occupies the low 8 bytes
/// (indices 24..32) of the 32-byte tag; the rest is zero. This is simple and
/// reversible — the timestamp round-trips back out of those 8 bytes — and orders
/// correctly: a later `create_time` yields a lexicographically greater tag.
#[must_use]
pub fn epoch_from_create_time(create_time_ns: u64) -> EpochTag {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&create_time_ns.to_be_bytes());
    EpochTag::from_bytes(bytes)
}

/// One node found by [`walk`]: its path components (filesystem names are bytes,
/// not guaranteed UTF-8), its filesystem id, and its metadata.
pub struct WalkEntry {
    /// Path components from the root, each a raw filesystem name.
    pub path: Vec<Vec<u8>>,
    /// The node's filesystem-specific id.
    pub id: FileId,
    /// The node's forensic metadata.
    pub meta: FsMeta,
}

/// Recursively enumerate every node of a mounted filesystem from the root — the
/// traversal a triage consumer runs over a resolved filesystem. Depth-capped and
/// visited-guarded against directory loops; `.`/`..` self/parent entries are
/// skipped. Returns the nodes; a per-node read error aborts loud.
///
/// # Errors
/// Propagates the first `read_dir`/`meta`/entry-stream error encountered.
pub fn walk(fs: &dyn FileSystem) -> VfsResult<Vec<WalkEntry>> {
    let mut out = Vec::new();
    let mut visited: HashSet<FileId> = HashSet::new();
    let mut stack: Vec<(Vec<Vec<u8>>, FileId, usize)> = vec![(Vec::new(), fs.root(), 0)];
    while let Some((prefix, dir_id, depth)) = stack.pop() {
        if depth > WALK_MAX_DEPTH || !visited.insert(dir_id) {
            continue;
        }
        for entry in fs.read_dir(dir_id)? {
            let entry = entry?;
            if matches!(entry.name.as_slice(), b"." | b"..") {
                continue;
            }
            let mut path = prefix.clone();
            path.push(entry.name);
            let meta = fs.meta(entry.id)?;
            let is_dir = matches!(meta.kind, NodeKind::Dir);
            out.push(WalkEntry {
                path: path.clone(),
                id: entry.id,
                meta,
            });
            if is_dir {
                stack.push((path, entry.id, depth + 1));
            }
        }
    }
    Ok(out)
}

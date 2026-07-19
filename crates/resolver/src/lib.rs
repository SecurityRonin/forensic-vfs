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
    ArchiveContents, Confidence, CredentialSource, DynSource, FileId, FileSystem, FsMeta, Layer,
    NoCredentials, NodeAddr, NodeKind, Openers, PathSpec, SnapshotRef, SniffWindow, VfsResult,
};

/// Depth cap on the recursive resolve (container/volume nesting) — a bomb guard.
const MAX_DEPTH: usize = 8;

/// Bytes read into the sniff window. Sized so a prober can see multi-offset
/// magics — notably the ISO 9660 Primary Volume Descriptor (`CD001` at byte
/// offset 32769, LBA 16). NTFS/ext4/MBR/GPT/container magics all sit in the
/// first few KiB, so the larger window is a strict superset. One bounded read.
const SNIFF_CAP: u64 = 128 * 1024;

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

/// One fully-peeled raw byte edge: the innermost [`DynSource`] no further
/// *packaging* layer (archive/compression or bare container) claims, plus its
/// locator (the archive-member / container layers it was unwrapped through). This
/// is the medium-agnostic terminal of [`SourceOpen::resolve_to_source`] — the raw
/// bytes a memory/log reader interprets, symmetric to the disk terminal's mounted
/// filesystem (ADR 0011).
pub struct ResolvedSource {
    /// The fully-unwrapped raw byte edge.
    pub source: DynSource,
    /// Its locator, topped by the last packaging layer it was peeled through.
    pub spec: PathSpec,
}

/// The generic layer resolver, exposed as an extension trait on the leaf's
/// [`Openers`]. Bring it into scope (`use forensic_vfs_resolver::SourceOpen;`) to
/// call `openers.open(source, spec, 0)`.
pub trait SourceOpen {
    /// Recursively resolve a source to a filesystem, supplying no credentials.
    /// A convenience wrapper over [`SourceOpen::open_with_credentials`] with the
    /// leaf's [`NoCredentials`] context: a signature-detected encryption layer then
    /// surfaces `NeedCredentials` loudly and a credential-attempt scheme falls
    /// through, so an encrypted volume is never silently skipped nor guessed.
    ///
    /// # Errors
    /// Propagates a source read error, or a prober `open`/decode failure raised
    /// after a positive probe verdict.
    fn open(&self, source: DynSource, spec: PathSpec, depth: usize) -> VfsResult<Option<Resolved>> {
        self.open_with_credentials(source, spec, depth, &NoCredentials)
    }

    /// Recursively resolve a source to a filesystem: sniff its head (and a tail
    /// window for trailer magics); if a filesystem prober recognizes it, mount it;
    /// otherwise if a volume-system prober recognizes it, descend into each volume
    /// and resolve that; otherwise attempt a signature-detected encryption layer,
    /// then containers, then archives; finally, as a last resort, attempt each
    /// signature-less credential-attempt encryption scheme so a wrong VeraCrypt
    /// guess can never shadow a real filesystem (ADR 0010). `Ok(None)` when nothing
    /// recognizes it — a genuinely clean unknown, not an error.
    ///
    /// Encryption failure semantics follow the probe verdict (ADR 0010): a `Yes`
    /// (BitLocker/LUKS/FileVault) whose decrypt fails propagates loud — the source
    /// *is* identified encryption and a wrong/absent key is a nameable condition —
    /// while a `Maybe` (VeraCrypt) whose decrypt fails falls through, because a
    /// failed decrypt of a signature-less scheme is indistinguishable from random
    /// data and must not break the empty-source contract.
    ///
    /// `creds` supplies keys/passphrases to any encryption layer reached.
    /// `depth` is the current nesting level; callers start at `0`. The recursion is
    /// depth-capped against a self-referential container/volume bomb.
    ///
    /// # Errors
    /// Propagates a source read error, or a prober `open`/decode failure raised
    /// after a positive (`Yes`) probe verdict.
    fn open_with_credentials(
        &self,
        source: DynSource,
        spec: PathSpec,
        depth: usize,
        creds: &dyn CredentialSource,
    ) -> VfsResult<Option<Resolved>>;

    /// Resolve a source to its innermost raw byte edge by peeling **only** the
    /// medium-agnostic packaging layers — archive/compression (ADR 0008) plus a
    /// bare container decode — and returning that [`ResolvedSource`] instead of
    /// requiring a filesystem mount (ADR 0011).
    ///
    /// This is the terminal a memory- or log-dump reader wants: `memf` receives
    /// the raw physical-page stream unwrapped from `memory.raw.gz` /
    /// `memory.zip` / `dump.7z` without re-implementing archive detection, then
    /// runs its own format detection over the bytes. It is orthogonal to the
    /// downstream medium — the same peel the disk [`SourceOpen::open`] path uses,
    /// stopping one step earlier.
    ///
    /// **Where it stops:** after archive and bare-container peeling only. It does
    /// **not** run the filesystem, volume-system, or encryption descent — those
    /// are disk *interpretation*, not packaging unwrap, and a memory dump is a
    /// single flat stream, not a partitioned/encrypted disk. A source that no
    /// packaging prober claims is its own terminal and is returned as-is (a bare
    /// `memory.raw` / `.dd`). Container decode is included because a container is a
    /// packaging wrapper over a flat stream; volume/encryption/filesystem are not.
    ///
    /// For a multi-member archive each member is tried in order and the first that
    /// peels to a terminal wins (the single-dump case); a caller wanting every
    /// member enumerates at the front-end.
    ///
    /// `depth` is the current nesting level; callers start at `0`. Past the
    /// packaging depth cap it yields `Ok(None)` (a self-referential-container bomb
    /// guard), symmetric with [`SourceOpen::open`].
    ///
    /// # Errors
    /// Propagates a source read error, or a container/archive `open`/decode failure
    /// raised after a positive probe verdict.
    fn resolve_to_source(
        &self,
        source: DynSource,
        spec: PathSpec,
        depth: usize,
    ) -> VfsResult<Option<ResolvedSource>>;
}

impl SourceOpen for Openers {
    fn open_with_credentials(
        &self,
        source: DynSource,
        spec: PathSpec,
        depth: usize,
        creds: &dyn CredentialSource,
    ) -> VfsResult<Option<Resolved>> {
        if depth > MAX_DEPTH {
            return Ok(None);
        }
        let (head, n, tail, tn, total) = read_sniff_buffers(&source)?;
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
                    if let Some(found) = self.open_with_credentials(sub, child, depth + 1, creds)? {
                        return Ok(Some(found));
                    }
                }
            }
        }
        // Encryption descent (ADR 0010), eager signature pass. `Maybe` schemes are
        // recorded for the last-resort pass below, so they never shadow a real fs.
        let mut credential_attempt: Vec<usize> = Vec::new();
        if let Some(found) = descend_signature_encryption(
            self,
            &window,
            &source,
            &spec,
            depth,
            creds,
            &mut credential_attempt,
        )? {
            return Ok(Some(found));
        }
        // Container + archive (ADR 0008) descent — the medium-agnostic packaging
        // peel, shared with `resolve_to_source` (ADR 0011). Here the continuation
        // is the FULL disk descent over each peeled child, so a container/archive
        // that wraps a filesystem still mounts it.
        if let Some(found) =
            descend_packaging(self, &window, &source, &spec, depth, &mut |src, sp, d| {
                self.open_with_credentials(src, sp, d, creds)
            })?
        {
            return Ok(Some(found));
        }
        // Encryption descent (ADR 0010), credential-attempt last resort — only
        // reached when nothing above claimed the source.
        descend_credential_attempt_encryption(
            self,
            &source,
            &spec,
            depth,
            creds,
            &credential_attempt,
        )
    }

    fn resolve_to_source(
        &self,
        source: DynSource,
        spec: PathSpec,
        depth: usize,
    ) -> VfsResult<Option<ResolvedSource>> {
        if depth > MAX_DEPTH {
            return Ok(None);
        }
        let (head, n, tail, tn, total) = read_sniff_buffers(&source)?;
        let window = SniffWindow::with_tail(
            0,
            head.get(..n).unwrap_or(&[]),
            total,
            tail.get(..tn).unwrap_or(&[]),
        );
        // Peel only the medium-agnostic packaging layers, re-entering
        // `resolve_to_source` (NOT the disk descent) on each peeled child.
        if let Some(found) =
            descend_packaging(self, &window, &source, &spec, depth, &mut |src, sp, d| {
                self.resolve_to_source(src, sp, d)
            })?
        {
            return Ok(Some(found));
        }
        // No packaging layer claimed it: this source is the raw terminal.
        Ok(Some(ResolvedSource { source, spec }))
    }
}

/// Try each container decoder, then each archive peeler, against `window`; for the
/// first prober that claims `source`, invoke `recurse` on the peeled child
/// source(s) with the layer-extended locator, returning its first `Some`. The
/// container/archive descent lives here once (ADR 0008/0011) so both the disk
/// filesystem terminal ([`SourceOpen::open_with_credentials`]) and the raw-source
/// terminal ([`SourceOpen::resolve_to_source`]) share it — `recurse` is the
/// caller's continuation (a full disk descent, or a packaging-only re-entry).
///
/// A bare gz/bz2 wrapper peels to one decoded [`ArchiveContents::Stream`] (1→1); a
/// multi-member archive peels to a [`ArchiveContents::Members`] table (1→N) whose
/// members are each tried in order (first that resolves wins). The selected member
/// index is recorded in the locator via `Layer::Archive { member }`, mirroring the
/// volume-system multi-volume descent. A free function, not a method, for the same
/// orphan-rule reason as [`SourceOpen`].
fn descend_packaging<T>(
    openers: &Openers,
    window: &SniffWindow,
    source: &DynSource,
    spec: &PathSpec,
    depth: usize,
    recurse: &mut dyn FnMut(DynSource, PathSpec, usize) -> VfsResult<Option<T>>,
) -> VfsResult<Option<T>> {
    for cd in openers.containers() {
        if cd.probe(window).is_candidate() {
            let decoded = cd.open(source.clone())?;
            let child = spec.clone().push(Layer::Container {
                format: cd.format(),
            });
            if let Some(found) = recurse(decoded, child, depth + 1)? {
                return Ok(Some(found));
            }
        }
    }
    for ar in openers.archives() {
        if ar.probe(window).is_candidate() {
            match ar.open(source.clone())? {
                ArchiveContents::Stream(inner) => {
                    let child = spec.clone().push(Layer::Archive { member: None });
                    if let Some(found) = recurse(inner, child, depth + 1)? {
                        return Ok(Some(found));
                    }
                }
                ArchiveContents::Members(members) => {
                    for (index, member) in members.into_iter().enumerate() {
                        let child = spec.clone().push(Layer::Archive {
                            member: Some(index),
                        });
                        if let Some(found) = recurse(member.source, child, depth + 1)? {
                            return Ok(Some(found));
                        }
                    }
                }
                // A future `#[non_exhaustive]` ArchiveContents variant this
                // resolver predates: fall through like an unrecognized source.
                _ => {} // cov:unreachable: no other ArchiveContents variant exists today
            }
        }
    }
    Ok(None)
}

/// The owned head/tail sniff buffers of a source, plus their filled lengths and
/// the source's total length: `(head, head_len, tail, tail_len, total_len)`. A
/// [`SniffWindow`] borrows the two buffers.
type SniffBuffers = (Vec<u8>, usize, Vec<u8>, usize, u64);

/// Read the head (up to [`SNIFF_CAP`]) and tail (up to [`TAIL_CAP`]) sniff buffers
/// of `source` in two bounded reads. The caller builds a [`SniffWindow`] borrowing
/// the returned buffers. The tail lets a prober match a trailer signature the head
/// never reaches — e.g. the DMG `koly` footer.
fn read_sniff_buffers(source: &DynSource) -> VfsResult<SniffBuffers> {
    let total = source.len();
    let cap = total.clamp(1, SNIFF_CAP) as usize;
    let mut head = vec![0u8; cap];
    let n = source.read_at(0, &mut head)?;
    let tail_cap = total.min(TAIL_CAP);
    let tail_start = total - tail_cap;
    let mut tail = vec![0u8; tail_cap as usize];
    let tn = source.read_at(tail_start, &mut tail)?;
    Ok((head, n, tail, tn, total))
}

/// Eager signature-encryption pass (ADR 0010): descend any `Yes`-verdict scheme
/// (BitLocker/LUKS/FileVault) and recurse on its decrypted plaintext, recording
/// each `Maybe`-verdict (signature-less) scheme's index into `credential_attempt`
/// for the last-resort pass. A `Yes` decrypt failure propagates loud (the source
/// *is* identified encryption), never a silent fall-through.
///
/// A free function rather than a method: `Openers` lives in the leaf, so the
/// resolver cannot add inherent methods to it (the orphan rule — the same reason
/// [`SourceOpen`] is an extension trait).
fn descend_signature_encryption(
    openers: &Openers,
    window: &SniffWindow,
    source: &DynSource,
    spec: &PathSpec,
    depth: usize,
    creds: &dyn CredentialSource,
    credential_attempt: &mut Vec<usize>,
) -> VfsResult<Option<Resolved>> {
    for (i, enc) in openers.encryption_layers().iter().enumerate() {
        match enc.probe(window) {
            Confidence::Yes { .. } => {
                let layer = enc.open(source.clone())?;
                let decrypted = layer.open(creds)?;
                let child = spec.clone().push(Layer::Encryption {
                    scheme: enc.scheme(),
                });
                if let Some(found) =
                    openers.open_with_credentials(decrypted, child, depth + 1, creds)?
                {
                    return Ok(Some(found));
                }
            }
            Confidence::Maybe => credential_attempt.push(i),
            Confidence::No => {}
        }
    }
    Ok(None)
}

/// Credential-attempt last-resort pass (ADR 0010): for each recorded `Maybe`
/// scheme (VeraCrypt), construct the layer and attempt to decrypt with `creds`,
/// recursing on success. A `Maybe` was never a positive identification, so a failed
/// *decrypt* means "not this scheme / wrong creds" — indistinguishable from random
/// data — and falls through to the next candidate, never breaking the empty-source
/// contract by erroring on an unrecognized blob. Constructing the layer, by
/// contrast, is loud (`?`): a construction failure is an unexpected internal error,
/// not a "wrong password", so it is surfaced rather than swallowed.
fn descend_credential_attempt_encryption(
    openers: &Openers,
    source: &DynSource,
    spec: &PathSpec,
    depth: usize,
    creds: &dyn CredentialSource,
    credential_attempt: &[usize],
) -> VfsResult<Option<Resolved>> {
    for &i in credential_attempt {
        let Some(enc) = openers.encryption_layers().get(i) else {
            continue; // cov:unreachable: indices came from this same slice
        };
        let layer = enc.open(source.clone())?;
        let Ok(decrypted) = layer.open(creds) else {
            continue;
        };
        let child = spec.clone().push(Layer::Encryption {
            scheme: enc.scheme(),
        });
        if let Some(found) = openers.open_with_credentials(decrypted, child, depth + 1, creds)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
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

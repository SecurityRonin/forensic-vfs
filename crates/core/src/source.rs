//! [`ImageSource`] — the universal read-only byte edge every layer speaks.
//!
//! A positioned-read stream: `read_at(&self, offset, buf)` carries no cursor, so
//! one source is shared across threads by `&self`. There is deliberately **no
//! write method** anywhere in this trait — evidence is read-only *by
//! construction*, not by convention. `Send + Sync` are supertraits, so
//! [`DynSource`] (`Arc<dyn ImageSource>`) is itself `Send + Sync` and composes
//! cleanly at every seam.

use std::sync::Arc;

use crate::error::VfsResult;

/// Stable identity for a source, for cache keying and lineage. Assigned by the
/// engine; a `SubRange`/decrypted/overlay source records this so a block cache
/// can account by identity rather than by accident of equal offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceId(u64);

impl SourceId {
    /// The base/root source of a lineage when no engine has assigned one yet.
    pub const ROOT: SourceId = SourceId(0);

    /// Wrap a raw id.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The raw id.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Default for SourceId {
    fn default() -> Self {
        Self::ROOT
    }
}

/// A borrowed, contiguous view into a source that owns whatever guard keeps it
/// alive, so a lent slice never dangles over an evicting cache (the round-1 fix
/// against a bare `&[u8]` tied to `&self`). Derefs to the bytes.
pub enum SourceView<'a> {
    /// A borrow of a memory-mapped region.
    Mmap(&'a [u8]),
    /// A reference-counted cache block plus the valid sub-range within it.
    Block(Arc<[u8]>, core::ops::Range<usize>),
}

impl core::ops::Deref for SourceView<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            SourceView::Mmap(s) => s,
            // The range is set by the producer to a valid sub-slice; fall back to
            // empty rather than panic if a future caller supplies a bad range.
            SourceView::Block(arc, r) => arc.get(r.clone()).unwrap_or(&[]),
        }
    }
}

/// One allocated extent `[offset, offset+len)` in a source's address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub offset: u64,
    pub len: u64,
}

/// The allocated-extent map of a source, so callers skip zero/sparse runs on
/// TB-scale images. A container reader reports real allocated runs; the default
/// is one dense extent covering the whole stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extents {
    runs: Vec<Extent>,
}

impl Extents {
    /// One extent covering `[0, len)` — the "everything is allocated" default.
    #[must_use]
    pub fn dense(len: u64) -> Self {
        if len == 0 {
            Self { runs: Vec::new() }
        } else {
            Self {
                runs: vec![Extent { offset: 0, len }],
            }
        }
    }

    /// Build from explicit runs.
    #[must_use]
    pub fn from_runs(runs: Vec<Extent>) -> Self {
        Self { runs }
    }

    /// The runs, in address order as supplied.
    #[must_use]
    pub fn runs(&self) -> &[Extent] {
        &self.runs
    }

    /// Total allocated bytes across all runs (saturating).
    #[must_use]
    pub fn allocated_len(&self) -> u64 {
        self.runs
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.len))
    }

    /// True when there are no allocated runs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }
}

/// A read-only, randomly-addressable byte stream: a decoded container, a
/// partition window, a decrypted volume, a VSS store, a file's data, or a byte
/// range of any of them. `Send + Sync`; positioned reads only; no writer.
pub trait ImageSource: Send + Sync {
    /// Logical size in bytes of this stream.
    fn len(&self) -> u64;

    /// True when the stream is zero-length.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fill `buf` starting at byte `offset`. Returns bytes read (0 at/after EOF).
    /// Never panics; a short read past EOF returns the available prefix length.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize>;

    /// Allocated-extent map. Default = one dense extent covering `[0, len)`.
    fn extents(&self) -> Extents {
        Extents::dense(self.len())
    }

    /// Optional zero-copy fast path. `None` when the backing cannot lend a
    /// contiguous view (the caller then uses [`ImageSource::read_at`]).
    fn view(&self, offset: u64, len: usize) -> Option<SourceView<'_>> {
        let _ = (offset, len);
        None
    }

    /// Stable identity for cache keying and lineage.
    fn source_id(&self) -> SourceId {
        SourceId::ROOT
    }
}

/// The object-safe shared handle used at every composition seam. `Arc`, not
/// `Box`: a child layer keeps a handle to its parent, and one parent backs many
/// children (every partition shares the disk source). `Send + Sync` because
/// [`ImageSource`] requires them.
pub type DynSource = Arc<dyn ImageSource>;

/// Read exactly `buf.len()` bytes at `offset`, erroring if the stream is too
/// short — the "give me all of it or fail loud" helper over the short-read
/// [`ImageSource::read_at`].
pub fn read_exact_at(src: &dyn ImageSource, offset: u64, buf: &mut [u8]) -> VfsResult<()> {
    let got = src.read_at(offset, buf)?;
    if got == buf.len() {
        Ok(())
    } else {
        Err(crate::error::VfsError::OutOfRange {
            what: "read_exact_at",
            offset,
            len: buf.len() as u64,
            bound: src.len(),
        })
    }
}

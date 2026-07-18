//! The archive-layer result contract — [`ArchiveContents`] and [`Member`].
//!
//! The [`crate::registry::ArchiveOpen`] trait peels an archive/compression
//! wrapper to one of these. A bare gzip/bzip2 stream yields a single decoded
//! [`ArchiveContents::Stream`] (1→1); a multi-member archive (tar/zip/7z) yields
//! its [`ArchiveContents::Members`] table (1→N). Either re-enters the resolver
//! exactly like a container decode. See ADR 0008 (archives resolve as a
//! first-class layer). This leaf carries only the contract types — every decoder
//! and its compression dependencies live in the `archive-core` adapter.

use crate::source::DynSource;

/// What an [`crate::registry::ArchiveOpen::open`] peel produces.
#[non_exhaustive]
pub enum ArchiveContents {
    /// A bare compression wrapper (gzip/bzip2): the single decoded stream. It
    /// re-enters resolution just like a decoded container — `E01.gz → E01 → …`.
    Stream(DynSource),
    /// A multi-member archive (tar/zip/7z): the member table. A member that is
    /// itself evidence (an `E01` inside a `.zip`) re-enters resolution on its own
    /// [`Member::source`].
    Members(Vec<Member>),
}

/// One member of a multi-member archive: its raw name and byte source. Archive
/// member names are bytes, not guaranteed UTF-8, so `name` is `Vec<u8>`.
pub struct Member {
    /// The member's raw (possibly non-UTF-8) name.
    pub name: Vec<u8>,
    /// The member's byte source, ready to re-enter resolution.
    pub source: DynSource,
}

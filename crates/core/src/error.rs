//! The one error type for the whole VFS stack.
//!
//! Panic-free (Paranoid Gatekeeper): every failure is a typed value carrying
//! enough context to diagnose it. Two rules from the fleet discipline are baked
//! into the shape here:
//!
//! - **Show the unrecognized value.** [`VfsError::Unrecognized`] and
//!   [`VfsError::Decode`] carry the actual offending bytes ([`SmallHex`]) plus
//!   the offset and layer — an "unknown magic" report is useless without them.
//! - **Bootstrap fails loud; only a per-node miss degrades.** A base/decode
//!   failure is [`VfsError::Bootstrap`]/[`VfsError::Decode`] (never an empty
//!   result), distinct from a genuinely-unrecognized node.

use core::fmt;

/// A short, inline snapshot of offending bytes for diagnostics — never a heap
/// allocation on the hot error path, and capped so a hostile stream cannot make
/// an error message unbounded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SmallHex {
    buf: [u8; Self::CAP],
    len: u8,
}

impl SmallHex {
    /// Maximum captured bytes; enough to identify a magic/signature.
    pub const CAP: usize = 16;

    /// Capture up to [`SmallHex::CAP`] bytes from `bytes` (a longer slice is
    /// truncated — the prefix is what identifies a signature). Never panics.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        let mut buf = [0u8; Self::CAP];
        let n = bytes.len().min(Self::CAP);
        // `n <= CAP` and `n <= bytes.len()`, so both slices are in bounds.
        buf[..n].copy_from_slice(&bytes[..n]);
        Self { buf, len: n as u8 }
    }

    /// The captured bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        // `len <= CAP` by construction, so the range is always valid.
        self.buf.get(..self.len as usize).unwrap_or(&[])
    }

    /// True when nothing was captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for SmallHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SmallHex(")?;
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for SmallHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for b in self.as_bytes() {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "{b:02x}")?;
            first = false;
        }
        Ok(())
    }
}

/// Every fallible operation in the VFS returns this. `#[non_exhaustive]` so a new
/// variant is an additive, non-breaking change.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum VfsError {
    /// An OS/backing read failed. `op` names the operation for triage.
    #[error("I/O during {op}: {source}")]
    Io {
        op: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// A prober said `Yes`/`Maybe` for this layer, then `open` failed to validate
    /// it. LOUD — never a silent downgrade to raw. Carries the offending bytes.
    #[error("decode failed in {layer} at offset {offset}: {detail} (bytes: {bytes})")]
    Decode {
        layer: &'static str,
        offset: u64,
        detail: String,
        bytes: SmallHex,
    },

    /// No prober recognized this source. The node is a typed `Unknown` leaf; the
    /// sniffed bytes are attached so an analyst can identify it by hand.
    #[error("unrecognized data at {at} offset {offset} (bytes: {bytes})")]
    Unrecognized {
        at: &'static str,
        offset: u64,
        bytes: SmallHex,
    },

    /// More than one prober returned `Yes` and `auto_pick` was off. The analyst
    /// disambiguates rather than the engine guessing.
    #[error("ambiguous detection: {candidates:?}")]
    Ambiguous { candidates: Vec<&'static str> },

    /// A prerequisite every downstream step depends on failed. ALWAYS loud; never
    /// absorbed into an empty result.
    #[error("bootstrap failed at {stage}: {detail}")]
    Bootstrap { stage: &'static str, detail: String },

    /// A required decoder is not compiled in (should not happen — batteries
    /// included). Loud, names the capability.
    #[error("unsupported {layer}: {scheme}")]
    Unsupported { layer: &'static str, scheme: String },

    /// A depth/source/byte cap tripped — a container/zip bomb, not a stack
    /// overflow or OOM.
    #[error("budget exceeded: {cap} (limit {limit})")]
    Budget { cap: &'static str, limit: u64 },

    /// A encryption layer needs credentials that were not supplied.
    #[error("credentials required for {scheme} ({target})")]
    NeedCredentials {
        scheme: &'static str,
        target: String,
    },

    /// An offset/length read past the addressable bound. Returned instead of a
    /// panic by the bounded readers.
    #[error("{what}: offset {offset}+{len} past bound {bound}")]
    OutOfRange {
        what: &'static str,
        offset: u64,
        len: u64,
        bound: u64,
    },
}

/// Convenience alias.
pub type VfsResult<T> = Result<T, VfsError>;

/// A `map_err` closure that wraps a [`std::io::Error`] as [`VfsError::Io`] with a
/// static operation label — one place to build the variant, so every I/O call
/// site is a one-liner.
pub(crate) fn io_err(op: &'static str) -> impl Fn(std::io::Error) -> VfsError {
    move |source| VfsError::Io { op, source }
}

#[cfg(test)]
mod tests {
    use super::io_err;

    #[test]
    fn io_err_wraps_with_the_op_label() {
        let e = io_err("read")(std::io::Error::other("boom"));
        assert!(format!("{e}").contains("read"));
    }
}

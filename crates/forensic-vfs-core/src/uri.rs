//! The lossless canonical URI form of a [`crate::PathSpec`] and its parser.
//!
//! `PathSpec` to `String` to `PathSpec` is byte-for-byte lossless (every reserved
//! byte, including `/` and `%`, is percent-encoded), so a spec pasted from a
//! report re-opens exactly. Round-trip is a test-enforced invariant.

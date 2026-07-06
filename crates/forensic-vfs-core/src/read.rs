//! Panic-free bounded integer readers over an untrusted byte slice.
//!
//! Every multi-byte read returns 0 when the requested window is out of range —
//! never a panic. This is the front door for every offset/length field parsed
//! from an attacker-controllable image.

#![no_main]
//! The bounded integer readers must never panic on any (data, offset) pair —
//! this is the panic-free foundation every reader parses offsets through. Drive
//! them with arbitrary bytes and an arbitrary offset derived from the input.

use forensic_vfs::read::{be_u16, be_u32, be_u64, le_u16, le_u32, le_u64};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Derive a spread of offsets from the data, including out-of-range ones.
    let offsets = [
        0usize,
        data.len(),
        data.len().wrapping_add(1),
        usize::MAX,
        data.first().copied().unwrap_or(0) as usize,
    ];
    for off in offsets {
        let _ = be_u16(data, off);
        let _ = be_u32(data, off);
        let _ = be_u64(data, off);
        let _ = le_u16(data, off);
        let _ = le_u32(data, off);
        let _ = le_u64(data, off);
    }
});

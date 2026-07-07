#![no_main]
//! The PathSpec URI parser is the leaf's attacker-controllable parse surface: a
//! spec string pasted from a report. `from_uri` over arbitrary bytes must never
//! panic, and anything it accepts must round-trip byte-for-byte back to itself.

use forensic_vfs::PathSpec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if let Ok(spec) = PathSpec::from_uri(&s) {
        // Round-trip invariant: to_uri(from_uri(x)) re-parses to the same spec.
        let reparsed = PathSpec::from_uri(&spec.to_uri()).expect("own output must re-parse");
        assert_eq!(reparsed, spec);
        // Display must not panic either.
        let _ = format!("{spec}");
    }
});

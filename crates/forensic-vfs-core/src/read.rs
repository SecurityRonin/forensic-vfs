//! Panic-free bounded integer readers over an untrusted byte slice.
//!
//! Every multi-byte read returns 0 when the requested window is out of range —
//! never a panic. This is the front door for every offset/length field parsed
//! from an attacker-controllable image.

#[cfg(test)]
mod tests {
    use super::{be_u16, be_u32, be_u64, le_u16, le_u32, le_u64};

    #[test]
    fn big_endian_reads_in_range() {
        assert_eq!(be_u16(&[0x12, 0x34], 0), 0x1234);
        assert_eq!(be_u32(&[0, 0, 1, 0], 0), 256);
        assert_eq!(
            be_u64(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], 0),
            0x0102_0304_0506_0708
        );
    }

    #[test]
    fn little_endian_reads_in_range() {
        assert_eq!(le_u16(&[0x34, 0x12], 0), 0x1234);
        assert_eq!(le_u32(&[0, 1, 0, 0], 0), 256);
        assert_eq!(
            le_u64(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01], 0),
            0x0102_0304_0506_0708
        );
    }

    #[test]
    fn reads_honor_offset() {
        assert_eq!(be_u16(&[0xaa, 0x12, 0x34], 1), 0x1234);
        assert_eq!(le_u32(&[0xff, 0xff, 0, 1, 0, 0], 2), 256);
    }

    #[test]
    fn out_of_range_returns_zero_never_panics() {
        // Too few bytes for the width.
        assert_eq!(be_u32(&[1, 2, 3], 0), 0);
        assert_eq!(be_u64(&[1, 2, 3, 4, 5, 6, 7], 0), 0);
        // Offset within the slice but window runs past the end.
        assert_eq!(be_u32(&[1, 2, 3, 4], 2), 0);
        assert_eq!(le_u16(&[1, 2], 2), 0);
        // Empty slice, offset past end.
        assert_eq!(be_u16(&[], 0), 0);
        assert_eq!(le_u32(&[1, 2, 3, 4], 100), 0);
    }

    #[test]
    fn offset_overflow_returns_zero() {
        // off + width overflowing usize must not panic.
        assert_eq!(be_u32(&[1, 2, 3, 4], usize::MAX), 0);
    }
}

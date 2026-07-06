//! Panic-free bounded integer readers over an untrusted byte slice.
//!
//! Every multi-byte read returns 0 when the requested window is out of range —
//! never a panic. This is the front door for every offset/length field parsed
//! from an attacker-controllable image.

/// Define a fixed-width integer reader that returns 0 when the window at `off`
/// is not fully in range (too short, offset past EOF, or `off + width`
/// overflowing `usize`) — never a panic.
macro_rules! bounded_reader {
    ($name:ident, $ty:ty, $width:literal, $from_bytes:ident) => {
        #[doc = concat!("Read a ", stringify!($ty), " at `off`; 0 if out of range. Never panics.")]
        #[must_use]
        pub fn $name(data: &[u8], off: usize) -> $ty {
            let Some(end) = off.checked_add($width) else {
                return 0;
            };
            match data.get(off..end) {
                Some(slice) => {
                    let mut buf = [0u8; $width];
                    buf.copy_from_slice(slice);
                    <$ty>::$from_bytes(buf)
                }
                None => 0,
            }
        }
    };
}

bounded_reader!(be_u16, u16, 2, from_be_bytes);
bounded_reader!(be_u32, u32, 4, from_be_bytes);
bounded_reader!(be_u64, u64, 8, from_be_bytes);
bounded_reader!(le_u16, u16, 2, from_le_bytes);
bounded_reader!(le_u32, u32, 4, from_le_bytes);
bounded_reader!(le_u64, u64, 8, from_le_bytes);

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

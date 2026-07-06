//! Concrete [`crate::ImageSource`] adapters: a positioned-read OS file, a byte
//! sub-range of a parent source, and a legacy `Read + Seek` cursor view.

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::Arc;

    use crate::error::VfsResult;
    use crate::source::{DynSource, ImageSource, SourceId};

    use super::{FileSource, SourceCursor, SubRange};

    /// In-memory test double: a byte vector presented as an ImageSource.
    struct MemSource(Vec<u8>);
    impl ImageSource for MemSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
            let Ok(off) = usize::try_from(offset) else {
                return Ok(0);
            };
            let Some(src) = self.0.get(off..) else {
                return Ok(0);
            };
            let n = src.len().min(buf.len());
            buf[..n].copy_from_slice(&src[..n]);
            Ok(n)
        }
    }

    fn mem(bytes: &[u8]) -> DynSource {
        Arc::new(MemSource(bytes.to_vec()))
    }

    #[test]
    fn subrange_windows_the_parent() {
        let base = mem(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let sr = SubRange::new(base, 2, 5);
        assert_eq!(sr.len(), 5);
        let mut buf = [0u8; 5];
        assert_eq!(sr.read_at(0, &mut buf).unwrap(), 5);
        assert_eq!(buf, [2, 3, 4, 5, 6]);
        // Offset within the window.
        let mut two = [0u8; 2];
        assert_eq!(sr.read_at(3, &mut two).unwrap(), 2);
        assert_eq!(two, [5, 6]);
    }

    #[test]
    fn subrange_clamps_reads_to_the_window() {
        let base = mem(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let sr = SubRange::new(base, 2, 5); // covers parent bytes [2,7)
        let mut buf = [0xffu8; 8];
        // Ask for 8 bytes from offset 3 — only 2 remain in the window.
        assert_eq!(sr.read_at(3, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], &[5, 6]);
        // Read at/after the window end yields 0.
        assert_eq!(sr.read_at(5, &mut buf).unwrap(), 0);
        assert_eq!(sr.read_at(99, &mut buf).unwrap(), 0);
    }

    #[test]
    fn subrange_len_is_clamped_to_parent_bounds() {
        let base = mem(&[0, 1, 2, 3]);
        // Ask for a window longer than the parent has from base=2.
        let sr = SubRange::new(base, 2, 100);
        assert_eq!(sr.len(), 2); // clamped to parent.len()-base
    }

    #[test]
    fn subrange_nests() {
        let base = mem(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let outer = Arc::new(SubRange::new(base, 2, 6)); // parent bytes [2,8)
        let inner = SubRange::new(outer, 1, 3); // outer bytes [1,4) = parent [3,6)
        let mut buf = [0u8; 3];
        assert_eq!(inner.read_at(0, &mut buf).unwrap(), 3);
        assert_eq!(buf, [3, 4, 5]);
    }

    #[test]
    fn filesource_reads_by_position() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(f.as_file_mut(), &[10, 20, 30, 40, 50]).unwrap();
        let fs = FileSource::open(f.path()).unwrap();
        assert_eq!(fs.len(), 5);
        assert_eq!(fs.source_id(), SourceId::ROOT);
        let mut buf = [0u8; 3];
        assert_eq!(fs.read_at(1, &mut buf).unwrap(), 3);
        assert_eq!(buf, [20, 30, 40]);
        // Past EOF: short read.
        let mut tail = [0u8; 4];
        assert_eq!(fs.read_at(3, &mut tail).unwrap(), 2);
        assert_eq!(&tail[..2], &[40, 50]);
        // Entirely past EOF: zero.
        assert_eq!(fs.read_at(100, &mut buf).unwrap(), 0);
    }

    #[test]
    fn sourcecursor_bridges_read_and_seek() {
        let base = mem(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut cur = SourceCursor::new(base, 2, 6); // window over parent [2,8)
        let mut first = [0u8; 3];
        cur.read_exact(&mut first).unwrap();
        assert_eq!(first, [2, 3, 4]);
        // Seek within the window and read the rest.
        assert_eq!(cur.seek(SeekFrom::Start(4)).unwrap(), 4);
        let mut rest = Vec::new();
        cur.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, vec![6, 7]);
        // SeekFrom::End clamps to the window length.
        assert_eq!(cur.seek(SeekFrom::End(0)).unwrap(), 6);
    }
}

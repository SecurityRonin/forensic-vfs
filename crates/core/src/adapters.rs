//! Concrete [`crate::ImageSource`] adapters: a positioned-read OS file, a byte
//! sub-range of a parent source, and a legacy `Read + Seek` cursor view.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use crate::error::{io_err, VfsResult};
use crate::source::{DynSource, ImageSource, SourceId};

/// A byte window `[base, base+len)` of a parent source, itself an
/// [`ImageSource`]. How a partition, VSS store, embedded image, or decrypted
/// volume is addressed. `len` is clamped to the parent's bounds at construction,
/// so a `read_at` can never escape the window.
pub struct SubRange {
    parent: DynSource,
    base: u64,
    len: u64,
}

impl SubRange {
    /// A window starting at `base` in `parent`, at most `len` bytes, clamped to
    /// whatever the parent actually has from `base`.
    #[must_use]
    pub fn new(parent: DynSource, base: u64, len: u64) -> Self {
        let available = parent.len().saturating_sub(base);
        Self {
            parent,
            base,
            len: len.min(available),
        }
    }
}

impl ImageSource for SubRange {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let remaining = self.len - offset;
        let want = (buf.len() as u64).min(remaining) as usize;
        let Some(dst) = buf.get_mut(..want) else {
            return Ok(0); // cov:unreachable: want <= buf.len() by the min above
        };
        let abs = self.base.saturating_add(offset);
        self.parent.read_at(abs, dst)
    }

    fn source_id(&self) -> SourceId {
        // Shares the parent's lineage so a block cache accounts by base source.
        self.parent.source_id()
    }
}

/// Wrap a raw OS file as an [`ImageSource`] using positioned reads
/// (`pread`/`seek_read`) — NOT a `Mutex<Seek>`, so parallel workers never
/// serialize on one cursor at the bottom of the stack.
pub struct FileSource {
    file: File,
    len: u64,
}

impl FileSource {
    /// Open `path` read-only as a base source.
    pub fn open(path: impl AsRef<Path>) -> VfsResult<Self> {
        let file = File::open(path).map_err(io_err("open"))?;
        Self::from_file(file)
    }

    /// Wrap an already-open file.
    pub fn from_file(file: File) -> VfsResult<Self> {
        let len = file.metadata().map_err(io_err("metadata"))?.len();
        Ok(Self { file, len })
    }
}

impl ImageSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        // Exactly one cfg block survives stripping and becomes the tail
        // expression — positioned reads, no cursor lock.
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file.read_at(buf, offset).map_err(io_err("read_at"))
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            self.file
                .seek_read(buf, offset)
                .map_err(io_err("seek_read"))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = buf;
            Err(crate::error::VfsError::Unsupported {
                layer: "FileSource",
                scheme: "positioned read".to_string(),
            })
        }
    }
}

/// A single-owner `Read + Seek` *view* over a [`DynSource`], for legacy
/// `analyse(&mut R)` / `build_filesystem(R)` call sites during migration. Clamped
/// to `[base, base+len)`; reads advance an internal cursor over positioned reads.
pub struct SourceCursor {
    src: DynSource,
    base: u64,
    len: u64,
    pos: u64,
}

impl SourceCursor {
    /// A cursor over the window `[base, base+len)` of `src` (clamped to the
    /// source's bounds), positioned at the start.
    #[must_use]
    pub fn new(src: DynSource, base: u64, len: u64) -> Self {
        let available = src.len().saturating_sub(base);
        Self {
            src,
            base,
            len: len.min(available),
            pos: 0,
        }
    }
}

impl Read for SourceCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let remaining = self.len - self.pos;
        let want = (buf.len() as u64).min(remaining) as usize;
        let Some(dst) = buf.get_mut(..want) else {
            return Ok(0); // cov:unreachable: want <= buf.len() by the min above
        };
        let abs = self.base.saturating_add(self.pos);
        let n = self.src.read_at(abs, dst).map_err(io::Error::other)?;
        self.pos = self.pos.saturating_add(n as u64);
        Ok(n)
    }
}

impl Seek for SourceCursor {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // i128 spans u64+i64 without overflow.
        let target: i128 = match pos {
            SeekFrom::Start(o) => i128::from(o),
            SeekFrom::End(o) => i128::from(self.len) + i128::from(o),
            SeekFrom::Current(o) => i128::from(self.pos) + i128::from(o),
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start of window",
            ));
        }
        self.pos = target.min(i128::from(u64::MAX)) as u64;
        Ok(self.pos)
    }
}

/// Wrap one or more legacy `Read + Seek` readers as an [`ImageSource`]. A
/// `read_at` checks out a free cursor from the pool (blocking on one if all are
/// busy), so parallel reads scale up to the pool size instead of serializing on
/// a single lock. A single-reader pool is a plain mutex. This is how a container
/// decoder (VHD/VMDK/QCOW2) hands its `Read + Seek` reader back as a `DynSource`.
pub struct SeekPoolSource<R: Read + Seek + Send> {
    pool: Vec<Mutex<R>>,
    len: u64,
}

impl<R: Read + Seek + Send> SeekPoolSource<R> {
    /// A pool of independent cursors over the same `len`-byte stream.
    #[must_use]
    pub fn new(readers: Vec<R>, len: u64) -> Self {
        Self {
            pool: readers.into_iter().map(Mutex::new).collect(),
            len,
        }
    }

    /// A single-cursor pool (a plain mutex).
    #[must_use]
    pub fn single(reader: R, len: u64) -> Self {
        Self::new(vec![reader], len)
    }

    fn checkout(&self) -> Option<std::sync::MutexGuard<'_, R>> {
        for m in &self.pool {
            if let Ok(g) = m.try_lock() {
                return Some(g);
            }
        }
        // All busy (or a single-cursor pool): block on the first, recovering a
        // poisoned lock instead of panicking.
        self.pool
            .first()
            .map(|m| m.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }
}

impl<R: Read + Seek + Send> ImageSource for SeekPoolSource<R> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let Some(mut guard) = self.checkout() else {
            return Ok(0); // cov:unreachable: the pool is non-empty by construction
        };
        guard
            .seek(SeekFrom::Start(offset))
            .map_err(io_err("seek"))?;
        let remaining = self.len - offset;
        let want = (buf.len() as u64).min(remaining) as usize;
        let Some(dst) = buf.get_mut(..want) else {
            return Ok(0); // cov:unreachable: want <= buf.len() by the min above
        };
        // Read::read may return short; loop to fill the window or hit EOF.
        let mut total = 0;
        while total < dst.len() {
            let Some(slot) = dst.get_mut(total..) else {
                break; // cov:unreachable: total < dst.len()
            };
            let n = guard.read(slot).map_err(io_err("read"))?;
            if n == 0 {
                break;
            }
            total += n;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::Arc;

    use crate::source::{DynSource, ImageSource, SourceId};

    use super::{FileSource, SeekPoolSource, SourceCursor, SubRange};

    /// A real tempfile-backed base source, so these tests exercise `FileSource`
    /// (positioned reads) rather than a hand-rolled in-memory double.
    fn mem(bytes: &[u8]) -> DynSource {
        use std::io::Write;
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(bytes).unwrap();
        Arc::new(FileSource::from_file(f).unwrap())
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
    #[test]
    fn seek_pool_source_bridges_read_seek_to_image_source() {
        use std::io::Cursor;
        let data: Vec<u8> = (0..=255).collect();
        let len = data.len() as u64;
        // Two independent cursors over the same bytes = a 2-reader pool.
        let pool = SeekPoolSource::new(
            vec![Cursor::new(data.clone()), Cursor::new(data.clone())],
            len,
        );
        assert_eq!(pool.len(), 256);
        let mut buf = [0u8; 4];
        assert_eq!(pool.read_at(10, &mut buf).unwrap(), 4);
        assert_eq!(buf, [10, 11, 12, 13]);
        // read past EOF -> 0
        assert_eq!(pool.read_at(256, &mut buf).unwrap(), 0);
        // usable as a DynSource (single-reader pool)
        let src: DynSource = Arc::new(SeekPoolSource::single(Cursor::new(data), len));
        let mut b2 = [0u8; 2];
        assert_eq!(src.read_at(254, &mut b2).unwrap(), 2);
        assert_eq!(b2, [254, 255]);
    }
}

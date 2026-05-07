use alloc::vec::Vec;

use arch_x86_64::{
    block::BlockAddress,
    frage::L0_PAGE_SIZE,
};

use crate::memory::{MappingFlags, MemorySegment};
use crate::memory::chunk::OwnedChunk;

use super::descriptor::{
    DescriptorBasic, DescriptorBasicOps,
    DescriptorRead, DescriptorReadOps, DescriptorSeek, DescriptorSeekOps, DescriptorWrite,
    DescriptorWriteOps, FileDescriptor, IoResult, SeekFrom,
};

const BLOCK_SIZE: usize = L0_PAGE_SIZE;

struct DataBlock {
    chunk: OwnedChunk,
    bytes_used: u32,
}

pub struct MemoryBackedFile<S: MemorySegment + 'static> {
    segment: &'static S,
    blocks: Vec<DataBlock>,
    total_bytes: u64,
    read_pos: u64,
}

impl<S: MemorySegment> MemoryBackedFile<S> {
    pub fn new_empty(segment: &'static S) -> Self {
        Self {
            segment,
            blocks: Vec::new(),
            total_bytes: 0,
            read_pos: 0,
        }
    }

    fn push_new_block(&mut self) -> Option<()> {
        let info = self.segment.map(BLOCK_SIZE, MappingFlags::READ | MappingFlags::WRITE)?;
        self.blocks.push(DataBlock { chunk: OwnedChunk::new(info), bytes_used: 0 });
        Some(())
    }
}

impl<S: MemorySegment> FileDescriptor for MemoryBackedFile<S> {
    fn basic_ext(&mut self) -> DescriptorBasicOps<'_> {
        self
    }

    fn read_ext(&mut self) -> Option<DescriptorReadOps<'_>> {
        Some(self)
    }

    fn write_ext(&mut self) -> Option<DescriptorWriteOps<'_>> {
        Some(self)
    }

    fn seek_ext(&mut self) -> Option<DescriptorSeekOps<'_>> {
        Some(self)
    }
}

impl<S: MemorySegment> DescriptorBasic for MemoryBackedFile<S> {
    fn close(&mut self) {}
}

impl<S: MemorySegment> DescriptorWrite for MemoryBackedFile<S> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let mut written = 0;

        while written < buf.len() {
            let needs_block = self.blocks.last().map_or(true, |b| b.bytes_used as usize >= BLOCK_SIZE);

            if needs_block && self.push_new_block().is_none() {
                break;
            }

            let block = self.blocks.last_mut().unwrap();
            let offset = block.bytes_used as usize;
            let to_copy = (BLOCK_SIZE - offset).min(buf.len() - written);
            let dst = block.chunk.memory().begin().as_u64() as *mut u8;

            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr().add(written), dst.add(offset), to_copy);
            }

            block.bytes_used += to_copy as u32;
            self.total_bytes += to_copy as u64;
            written += to_copy;
        }

        Ok(written)
    }

    fn flish(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl<S: MemorySegment> DescriptorRead for MemoryBackedFile<S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let mut read_count = 0;
        let mut block_start: u64 = 0;
        let mut pos = self.read_pos;

        'outer: for block in &self.blocks {
            let block_end = block_start + block.bytes_used as u64;
            if pos < block_end {
                let offset_in_block = (pos - block_start) as usize;
                let to_read = (block.bytes_used as usize - offset_in_block).min(buf.len() - read_count);
                let src = block.chunk.memory().begin().as_u64() as *const u8;

                unsafe {
                    core::ptr::copy_nonoverlapping(src.add(offset_in_block), buf.as_mut_ptr().add(read_count), to_read);
                }

                read_count += to_read;
                pos += to_read as u64;
                if read_count >= buf.len() {
                    break 'outer;
                }
            }
            block_start = block_end;
        }

        self.read_pos = pos;
        Ok(read_count)
    }
}

impl<S: MemorySegment> DescriptorSeek for MemoryBackedFile<S> {
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        self.read_pos = match pos {
            SeekFrom::Start(n) => n.min(self.total_bytes),
            SeekFrom::End(n) => (self.total_bytes as i64 + n).max(0) as u64,
            SeekFrom::Current(n) => (self.read_pos as i64 + n).max(0) as u64,
        };
        Ok(self.read_pos)
    }
}

impl<S: MemorySegment> Drop for MemoryBackedFile<S> {
    fn drop(&mut self) {
        for block in self.blocks.drain(..) {
            self.segment.unmap(block.chunk.extract_info());
        }
    }
}

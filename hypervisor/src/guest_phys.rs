use core::{marker::PhantomData, mem::MaybeUninit, ops::Range};

use arch_x86_64::{
    addr::PhysAddr,
    block::{
        Align, AlignedChunkable, Alignment, AnyAlign, BackedBlock, Block, BlockAddress,
        BlockChunks, Chunkable, DynamicSize, FixedSize, Size,
    },
    frage,
};
use common::align_marker::AlignMarker;

pub struct GuestPhys;

#[derive(Clone, Copy, Debug)]
pub struct GuestPhysBlock<'a, Sz: Size = DynamicSize, Al: Align = AnyAlign> {
    guest_base: PhysAddr,
    host_ptr: *mut MaybeUninit<u8>,
    size: u64,
    _block: PhantomData<(&'a (), Sz, Al)>,
}

impl<'a, Sz: Size, Al: Align> GuestPhysBlock<'a, Sz, Al> {
    pub unsafe fn new_unchecked(
        guest_base: PhysAddr,
        host_ptr: *mut MaybeUninit<u8>,
        size: u64,
    ) -> Self {
        GuestPhysBlock {
            guest_base,
            host_ptr,
            size,
            _block: PhantomData,
        }
    }
}

impl<'a, Al: Align> GuestPhysBlock<'a, DynamicSize, Al> {
    pub unsafe fn try_from_raw(
        guest_base: PhysAddr,
        host_ptr: *mut MaybeUninit<u8>,
        size: u64,
    ) -> Option<Self> {
        Al::check(guest_base.as_u64() as usize)
            .then(|| unsafe { Self::new_unchecked(guest_base, host_ptr, size) })
    }

    pub fn from_raw(guest_base: PhysAddr, host_ptr: *mut MaybeUninit<u8>, size: u64) -> Self {
        unsafe { Self::try_from_raw(guest_base, host_ptr, size).unwrap() }
    }

    pub fn try_from_slice(
        guest_base: PhysAddr,
        host_memory: &mut [MaybeUninit<u8>],
    ) -> Option<Self> {
        unsafe {
            Self::try_from_raw(
                guest_base,
                host_memory.as_mut_ptr(),
                host_memory.len() as u64,
            )
        }
    }

    pub fn from_slice(guest_base: PhysAddr, host_memory: &mut [MaybeUninit<u8>]) -> Self {
        Self::try_from_slice(guest_base, host_memory).unwrap()
    }
}

impl<'a, const N: usize, Al: Align> GuestPhysBlock<'a, FixedSize<N>, Al> {
    pub fn try_from_array(
        guest_base: PhysAddr,
        host_memory: &mut [MaybeUninit<u8>; N],
    ) -> Option<Self> {
        Al::check(guest_base.as_u64() as usize)
            .then(|| unsafe { Self::new_unchecked(guest_base, host_memory.as_mut_ptr(), N as u64) })
    }

    pub fn from_array(guest_base: PhysAddr, host_memory: &mut [MaybeUninit<u8>; N]) -> Self {
        Self::try_from_array(guest_base, host_memory).unwrap()
    }
}

impl<'a, Sz: Size, Al: Align> Block<GuestPhys, Sz, Al> for GuestPhysBlock<'a, Sz, Al> {
    fn byte_len(&self) -> u64 {
        self.size
    }

    unsafe fn cast_state<Sz2: Size, Al2: Align>(self) -> impl Block<GuestPhys, Sz2, Al2> {
        unsafe { GuestPhysBlock::new_unchecked(self.guest_base, self.host_ptr, self.size) }
    }
}

impl<'a, Sz: Size, Al: Align> BlockAddress<GuestPhys> for GuestPhysBlock<'a, Sz, Al> {
    type Addr = PhysAddr;

    fn begin(&self) -> PhysAddr {
        self.guest_base
    }

    fn range(&self) -> Range<PhysAddr> {
        self.guest_base..self.guest_base + self.size
    }
}

unsafe impl<'a, Sz: Size, Al: Align> BackedBlock<GuestPhys, Sz, Al> for GuestPhysBlock<'a, Sz, Al> {
    fn as_uninit_ptr(&self) -> *const [MaybeUninit<u8>] {
        core::ptr::slice_from_raw_parts(self.host_ptr as *const MaybeUninit<u8>, self.size as usize)
    }

    fn as_uninit_ptr_mut(&mut self) -> *mut [MaybeUninit<u8>] {
        core::ptr::slice_from_raw_parts_mut(self.host_ptr, self.size as usize)
    }
}

impl<'a, Sz: Size, Al: Align> Chunkable<GuestPhys, Sz, Al> for GuestPhysBlock<'a, Sz, Al> {
    type Chunks<ChunkSz: Size> = GuestPhysChunks<'a, ChunkSz, AnyAlign>;

    fn chunk_by(self, k: u64) -> Self::Chunks<DynamicSize> {
        assert!(k > 0);
        assert_eq!(self.size % k, 0);
        unsafe {
            GuestPhysChunks::new_unchecked(
                self.guest_base,
                self.host_ptr,
                k,
                (self.size / k) as usize,
            )
        }
    }

    fn chunk_by_fixed<const N: usize>(self) -> Self::Chunks<FixedSize<N>> {
        assert!(N > 0);
        assert_eq!(self.size % N as u64, 0);
        unsafe {
            GuestPhysChunks::new_unchecked(
                self.guest_base,
                self.host_ptr,
                N as u64,
                self.size as usize / N,
            )
        }
    }
}

impl<'a, Sz: Size, const M: usize> AlignedChunkable<GuestPhys, Sz, M>
    for GuestPhysBlock<'a, Sz, Alignment<M>>
{
    type AlignedChunks<ChunkSz: Size> = GuestPhysChunks<'a, ChunkSz, Alignment<M>>;

    fn chunk_by_aligned(self, k: u64) -> Self::AlignedChunks<DynamicSize> {
        assert!(k > 0);
        assert_eq!(self.size % k, 0);
        assert_eq!(k % M as u64, 0);
        unsafe {
            GuestPhysChunks::new_unchecked(
                self.guest_base,
                self.host_ptr,
                k,
                (self.size / k) as usize,
            )
        }
    }

    fn chunk_by_fixed_aligned<const N: usize>(self) -> Self::AlignedChunks<FixedSize<N>> {
        assert!(N > 0);
        assert_eq!(self.size % N as u64, 0);
        assert_eq!(N % M, 0);
        unsafe {
            GuestPhysChunks::new_unchecked(
                self.guest_base,
                self.host_ptr,
                N as u64,
                self.size as usize / N,
            )
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GuestPhysChunks<'a, Sz: Size, Al: Align> {
    guest_base: PhysAddr,
    host_ptr: *mut MaybeUninit<u8>,
    chunk_size: u64,
    count: usize,
    _block: PhantomData<(&'a (), Sz, Al)>,
}

pub struct GuestPhysChunksIter<'a, Sz: Size, Al: Align> {
    chunks: GuestPhysChunks<'a, Sz, Al>,
    index: usize,
}

impl<'a, Sz: Size, Al: Align> GuestPhysChunks<'a, Sz, Al> {
    pub unsafe fn new_unchecked(
        guest_base: PhysAddr,
        host_ptr: *mut MaybeUninit<u8>,
        chunk_size: u64,
        count: usize,
    ) -> Self {
        GuestPhysChunks {
            guest_base,
            host_ptr,
            chunk_size,
            count,
            _block: PhantomData,
        }
    }
}

impl<'a, Sz: Size, Al: Align> BlockChunks<GuestPhys, Sz, Al> for GuestPhysChunks<'a, Sz, Al> {
    type Block<BlSz: Size, BlAl: Align> = GuestPhysBlock<'a, BlSz, BlAl>;

    fn len(&self) -> usize {
        self.count
    }

    fn at(&self, index: usize) -> Self::Block<Sz, Al> {
        assert!(index < self.count);
        unsafe {
            GuestPhysBlock::new_unchecked(
                self.guest_base + index as u64 * self.chunk_size,
                self.host_ptr.add(index * self.chunk_size as usize),
                self.chunk_size,
            )
        }
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        assert!(index <= self.count);
        unsafe {
            (
                Self::new_unchecked(self.guest_base, self.host_ptr, self.chunk_size, index),
                Self::new_unchecked(
                    self.guest_base + index as u64 * self.chunk_size,
                    self.host_ptr.add(index * self.chunk_size as usize),
                    self.chunk_size,
                    self.count - index,
                ),
            )
        }
    }

    fn into_block(self) -> Self::Block<DynamicSize, Al> {
        unsafe {
            GuestPhysBlock::new_unchecked(
                self.guest_base,
                self.host_ptr,
                self.count as u64 * self.chunk_size,
            )
        }
    }
}

impl<'a, Sz: Size, Al: Align> IntoIterator for GuestPhysChunks<'a, Sz, Al> {
    type Item = GuestPhysBlock<'a, Sz, Al>;
    type IntoIter = GuestPhysChunksIter<'a, Sz, Al>;

    fn into_iter(self) -> GuestPhysChunksIter<'a, Sz, Al> {
        GuestPhysChunksIter {
            chunks: self,
            index: 0,
        }
    }
}

impl<'a, Sz: Size, Al: Align> Iterator for GuestPhysChunksIter<'a, Sz, Al> {
    type Item = GuestPhysBlock<'a, Sz, Al>;

    fn next(&mut self) -> Option<Self::Item> {
        (self.index < self.chunks.count).then(|| {
            let block = self.chunks.at(self.index);
            self.index += 1;
            block
        })
    }
}

impl<'a, const SIZE: usize, Al: Align> GuestPhysBlock<'a, FixedSize<SIZE>, Al>
where
    frage::PageAligment: AlignMarker<SIZE>,
{
    pub fn into_frame(self) -> frage::Frame<SIZE> {
        frage::Frame::new(self.begin())
    }

    pub fn into_page_ref(self) -> &'a frage::Page<SIZE> {
        let ptr = self.host_ptr as *const frage::Page<SIZE>;
        unsafe { ptr.as_ref().unwrap() }
    }

    pub fn into_page_mut(self) -> &'a mut frage::Page<SIZE> {
        let mut_ptr = self.host_ptr as *mut frage::Page<SIZE>;
        unsafe { mut_ptr.as_mut().unwrap() }
    }
}

use crate::{
    addr::{PhysAddr, VirtAddr},
    block::{
        Align, AlignedChunkable, Alignment, AnyAlign, BackedBlock, Block, BlockAddress,
        BlockChunks, Chunkable, DynamicSize, FixedSize, Size,
    },
    pte::{PAGE_OFFSET_BITS, PAGE_TABLE_INDEX_BITS},
};

use core::{marker::PhantomData, mem::MaybeUninit, ops::Range, ptr};

use common::{align_marker::AlignMarker, define_align};

pub struct PageAligment;

define_align!(AlignL0, PageAligment, 0x1000, L0_PAGE_SIZE);
define_align!(AlignL1, PageAligment, 0x200000, L1_HUGE_PAGE_SIZE);
// AlignL2 (and L2 pages) cannot be expressed as aligned to 1<<30 slice because aligment is limited to <= 1<<29
// But it doesn't seem usefull anyways

#[derive(Debug, Clone, Copy)]
pub struct Frame<const SIZE: usize> {
    base: PhysAddr,
}

pub type L0Frame = Frame<L0_PAGE_SIZE>;

pub struct Page<const SIZE: usize>
where
    PageAligment: AlignMarker<SIZE>,
{
    memory: [MaybeUninit<u8>; SIZE],
    _align: <PageAligment as AlignMarker<SIZE>>::Marker,
}

impl<const SIZE: usize> Frame<SIZE> {
    pub const SIZE: u64 = SIZE as u64;

    pub fn new(phys: PhysAddr) -> Self {
        Self::try_new(phys).unwrap()
    }

    pub fn try_new(phys: PhysAddr) -> Option<Self> {
        if phys.is_aligned(Self::SIZE) {
            Some(Self { base: phys })
        } else {
            None
        }
    }

    pub fn new_containing(phys: PhysAddr) -> Self {
        Self::new(phys.align_down(Self::SIZE))
    }

    pub fn base_address(&self) -> PhysAddr {
        self.base
    }
}

impl<const SIZE: usize> Page<SIZE>
where
    PageAligment: AlignMarker<SIZE>,
{
    pub const SIZE: u64 = SIZE as u64;

    pub fn bytes_ref(&self) -> &[MaybeUninit<u8>; SIZE] {
        &self.memory
    }

    pub fn bytes_mut(&mut self) -> &mut [MaybeUninit<u8>; SIZE] {
        &mut self.memory
    }
}

pub type L0Page = Page<L0_PAGE_SIZE>;
pub type L1HugePage = Page<L1_HUGE_PAGE_SIZE>;

pub const L0_PAGE_SIZE: usize = 1 << PAGE_OFFSET_BITS; // 4KiB
pub const L1_HUGE_PAGE_SIZE: usize = L0_PAGE_SIZE << PAGE_TABLE_INDEX_BITS; // 2MiB

pub struct Phys;
pub struct Virt;

#[derive(Debug, Clone, Copy)]
pub struct PhysBlock<Sz: Size = DynamicSize, Al: Align = AnyAlign> {
    base: PhysAddr,
    size: u64,
    _block: PhantomData<(Sz, Al)>,
}

impl<Sz: Size, Al: Align> PhysBlock<Sz, Al> {
    pub unsafe fn new_unchecked(base: PhysAddr, size: u64) -> Self {
        PhysBlock {
            base,
            size,
            _block: PhantomData,
        }
    }
}

impl<Al: Align> PhysBlock<DynamicSize, Al> {
    pub fn new(base: PhysAddr, size: u64) -> Self {
        Self::try_new(base, size).unwrap()
    }

    pub fn try_new(base: PhysAddr, size: u64) -> Option<Self> {
        Al::check(base.as_u64() as usize).then(|| unsafe { Self::new_unchecked(base, size) })
    }
}

impl<const N: usize, Al: Align> PhysBlock<FixedSize<N>, Al> {
    pub fn new(base: PhysAddr) -> Self {
        Self::try_new(base).unwrap()
    }

    pub fn try_new(base: PhysAddr) -> Option<Self> {
        Al::check(base.as_u64() as usize).then(|| unsafe { Self::new_unchecked(base, N as u64) })
    }
}

impl<Sz: Size, Al: Align> Block<Phys, Sz, Al> for PhysBlock<Sz, Al> {
    fn byte_len(&self) -> u64 {
        self.size
    }

    unsafe fn cast_state<Sz2: Size, Al2: Align>(self) -> impl Block<Phys, Sz2, Al2> {
        unsafe { PhysBlock::new_unchecked(self.base, self.size) }
    }
}

impl<Sz: Size, Al: Align> BlockAddress<Phys> for PhysBlock<Sz, Al> {
    type Addr = PhysAddr;

    fn begin(&self) -> PhysAddr {
        self.base
    }

    fn range(&self) -> Range<PhysAddr> {
        self.base..self.base + self.size
    }
}

impl<Sz: Size, Al: Align> Chunkable<Phys, Sz, Al> for PhysBlock<Sz, Al> {
    type Chunks<ChunkSz: Size> = PhysChunks<ChunkSz, AnyAlign>;

    fn chunk_by(self, k: u64) -> Self::Chunks<DynamicSize> {
        assert!(k > 0);
        assert_eq!(self.size % k, 0);
        unsafe { PhysChunks::new_unchecked(self.base, k, (self.size / k) as usize) }
    }

    fn chunk_by_fixed<const N: usize>(self) -> Self::Chunks<FixedSize<N>> {
        assert!(N > 0);
        assert_eq!(self.size % N as u64, 0);
        unsafe { PhysChunks::new_unchecked(self.base, N as u64, self.size as usize / N) }
    }
}

impl<Sz: Size, const M: usize> AlignedChunkable<Phys, Sz, M> for PhysBlock<Sz, Alignment<M>> {
    type AlignedChunks<ChunkSz: Size> = PhysChunks<ChunkSz, Alignment<M>>;

    fn chunk_by_aligned(self, k: u64) -> Self::AlignedChunks<DynamicSize> {
        assert!(k > 0);
        assert_eq!(self.size % k, 0);
        assert_eq!(k % M as u64, 0);
        unsafe { PhysChunks::new_unchecked(self.base, k, (self.size / k) as usize) }
    }

    fn chunk_by_fixed_aligned<const N: usize>(self) -> Self::AlignedChunks<FixedSize<N>> {
        assert!(N > 0);
        assert_eq!(self.size % N as u64, 0);
        assert_eq!(N % M, 0);
        unsafe { PhysChunks::new_unchecked(self.base, N as u64, self.size as usize / N) }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct PhysChunks<Sz: Size, Al: Align> {
    base: PhysAddr,
    chunk_size: u64,
    count: usize,
    _block: PhantomData<(Sz, Al)>,
}

pub struct PhysChunksIter<Sz: Size, Al: Align> {
    chunks: PhysChunks<Sz, Al>,
    index: usize,
}

impl<Sz: Size, Al: Align> PhysChunks<Sz, Al> {
    pub unsafe fn new_unchecked(base: PhysAddr, chunk_size: u64, count: usize) -> Self {
        PhysChunks {
            base,
            chunk_size,
            count,
            _block: PhantomData,
        }
    }
}

impl<Sz: Size, Al: Align> BlockChunks<Phys, Sz, Al> for PhysChunks<Sz, Al> {
    type Block<BlSz: Size, BlAl: Align> = PhysBlock<BlSz, BlAl>;

    fn len(&self) -> usize {
        self.count
    }

    fn at(&self, index: usize) -> PhysBlock<Sz, Al> {
        assert!(index < self.count);
        unsafe {
            PhysBlock::new_unchecked(self.base + index as u64 * self.chunk_size, self.chunk_size)
        }
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        assert!(index <= self.count);
        unsafe {
            (
                Self::new_unchecked(self.base, self.chunk_size, index),
                Self::new_unchecked(
                    self.base + index as u64 * self.chunk_size,
                    self.chunk_size,
                    self.count - index,
                ),
            )
        }
    }

    fn into_block(self) -> Self::Block<DynamicSize, Al> {
        unsafe { PhysBlock::new_unchecked(self.base, self.count as u64 * self.chunk_size) }
    }
}

impl<Sz: Size, Al: Align> IntoIterator for PhysChunks<Sz, Al> {
    type Item = PhysBlock<Sz, Al>;
    type IntoIter = PhysChunksIter<Sz, Al>;

    fn into_iter(self) -> PhysChunksIter<Sz, Al> {
        PhysChunksIter {
            chunks: self,
            index: 0,
        }
    }
}

impl<Sz: Size, Al: Align> Iterator for PhysChunksIter<Sz, Al> {
    type Item = PhysBlock<Sz, Al>;

    fn next(&mut self) -> Option<Self::Item> {
        (self.index < self.chunks.count).then(|| {
            let block = self.chunks.at(self.index);
            self.index += 1;
            block
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VirtBlock<'a, Sz: Size = DynamicSize, Al: Align = AnyAlign> {
    base: VirtAddr,
    size: u64,
    _block: PhantomData<(&'a (), Sz, Al)>,
}

impl<'a, Sz: Size, Al: Align> VirtBlock<'a, Sz, Al> {
    pub unsafe fn new_unchecked(base: VirtAddr, size: u64) -> Self {
        VirtBlock {
            base,
            size,
            _block: PhantomData,
        }
    }
}

impl<'a, Al: Align> VirtBlock<'a, DynamicSize, Al> {
    pub fn new(base: VirtAddr, size: u64) -> Self {
        Self::try_new(base, size).unwrap()
    }

    pub fn try_new(base: VirtAddr, size: u64) -> Option<Self> {
        Al::check(base.as_u64() as usize).then(|| unsafe { Self::new_unchecked(base, size) })
    }
}

impl<'a, const N: usize, Al: Align> VirtBlock<'a, FixedSize<N>, Al> {
    pub fn new(base: VirtAddr) -> Self {
        Self::try_new(base).unwrap()
    }

    pub fn try_new(base: VirtAddr) -> Option<Self> {
        Al::check(base.as_u64() as usize).then(|| unsafe { Self::new_unchecked(base, N as u64) })
    }
}

impl<'a> VirtBlock<'a, DynamicSize, AnyAlign> {
    pub fn from_slice(slice: &'a mut [MaybeUninit<u8>]) -> Self {
        unsafe { VirtBlock::new_unchecked(VirtAddr::from_ptr(slice.as_ptr()), slice.len() as u64) }
    }
}

impl<'a, Sz: Size, Al: Align> Block<Virt, Sz, Al> for VirtBlock<'a, Sz, Al> {
    fn byte_len(&self) -> u64 {
        self.size
    }

    unsafe fn cast_state<Sz2: Size, Al2: Align>(self) -> impl Block<Virt, Sz2, Al2> {
        unsafe { VirtBlock::new_unchecked(self.base, self.size) }
    }
}

impl<'a, Sz: Size, Al: Align> BlockAddress<Virt> for VirtBlock<'a, Sz, Al> {
    type Addr = VirtAddr;

    fn begin(&self) -> VirtAddr {
        self.base
    }

    fn range(&self) -> Range<VirtAddr> {
        self.base..self.base + self.size
    }
}

unsafe impl<'a, Sz: Size, Al: Align> BackedBlock<Virt, Sz, Al> for VirtBlock<'a, Sz, Al> {
    fn as_uninit_ptr(&self) -> *const [MaybeUninit<u8>] {
        ptr::slice_from_raw_parts(self.base.as_ptr::<MaybeUninit<u8>>(), self.size as usize)
    }

    fn as_uninit_ptr_mut(&mut self) -> *mut [MaybeUninit<u8>] {
        ptr::slice_from_raw_parts_mut(
            self.base.as_mut_ptr::<MaybeUninit<u8>>(),
            self.size as usize,
        )
    }
}

impl<'a, Sz: Size, Al: Align> Chunkable<Virt, Sz, Al> for VirtBlock<'a, Sz, Al> {
    type Chunks<ChunkSz: Size> = VirtChunks<'a, ChunkSz, AnyAlign>;

    fn chunk_by(self, k: u64) -> Self::Chunks<DynamicSize> {
        assert!(k > 0);
        assert_eq!(self.size % k, 0);
        unsafe { VirtChunks::new_unchecked(self.base, k, (self.size / k) as usize) }
    }

    fn chunk_by_fixed<const N: usize>(self) -> Self::Chunks<FixedSize<N>> {
        assert!(N > 0);
        assert_eq!(self.size % N as u64, 0);
        unsafe { VirtChunks::new_unchecked(self.base, N as u64, self.size as usize / N) }
    }
}

impl<'a, Sz: Size, const M: usize> AlignedChunkable<Virt, Sz, M>
    for VirtBlock<'a, Sz, Alignment<M>>
{
    type AlignedChunks<ChunkSz: Size> = VirtChunks<'a, ChunkSz, Alignment<M>>;

    fn chunk_by_aligned(self, k: u64) -> Self::AlignedChunks<DynamicSize> {
        assert!(k > 0);
        assert_eq!(self.size % k, 0);
        assert_eq!(k % M as u64, 0);
        unsafe { VirtChunks::new_unchecked(self.base, k, (self.size / k) as usize) }
    }

    fn chunk_by_fixed_aligned<const N: usize>(self) -> Self::AlignedChunks<FixedSize<N>> {
        assert!(N > 0);
        assert_eq!(self.size % N as u64, 0);
        assert_eq!(N % M, 0);
        unsafe { VirtChunks::new_unchecked(self.base, N as u64, self.size as usize / N) }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VirtChunks<'a, Sz: Size, Al: Align> {
    base: VirtAddr,
    chunk_size: u64,
    count: usize,
    _block: PhantomData<(&'a (), Sz, Al)>,
}

pub struct VirtChunksIter<'a, Sz: Size, Al: Align> {
    chunks: VirtChunks<'a, Sz, Al>,
    index: usize,
}

impl<'a, Sz: Size, Al: Align> VirtChunks<'a, Sz, Al> {
    pub unsafe fn new_unchecked(base: VirtAddr, chunk_size: u64, count: usize) -> Self {
        VirtChunks {
            base,
            chunk_size,
            count,
            _block: PhantomData,
        }
    }
}

impl<'a, Sz: Size, Al: Align> BlockChunks<Virt, Sz, Al> for VirtChunks<'a, Sz, Al> {
    type Block<BlSz: Size, BlAl: Align> = VirtBlock<'a, BlSz, BlAl>;

    fn len(&self) -> usize {
        self.count
    }

    fn at(&self, index: usize) -> Self::Block<Sz, Al> {
        assert!(index < self.count);
        unsafe {
            VirtBlock::new_unchecked(self.base + index as u64 * self.chunk_size, self.chunk_size)
        }
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        assert!(index <= self.count);
        unsafe {
            (
                Self::new_unchecked(self.base, self.chunk_size, index),
                Self::new_unchecked(
                    self.base + index as u64 * self.chunk_size,
                    self.chunk_size,
                    self.count - index,
                ),
            )
        }
    }

    fn into_block(self) -> Self::Block<DynamicSize, Al> {
        unsafe { VirtBlock::new_unchecked(self.base, self.count as u64 * self.chunk_size) }
    }
}

impl<'a, Sz: Size, Al: Align> IntoIterator for VirtChunks<'a, Sz, Al> {
    type Item = VirtBlock<'a, Sz, Al>;
    type IntoIter = VirtChunksIter<'a, Sz, Al>;

    fn into_iter(self) -> VirtChunksIter<'a, Sz, Al> {
        VirtChunksIter {
            chunks: self,
            index: 0,
        }
    }
}

impl<'a, Sz: Size, Al: Align> Iterator for VirtChunksIter<'a, Sz, Al> {
    type Item = VirtBlock<'a, Sz, Al>;

    fn next(&mut self) -> Option<Self::Item> {
        (self.index < self.chunks.count).then(|| {
            let block = self.chunks.at(self.index);
            self.index += 1;
            block
        })
    }
}

impl<const SIZE: usize> Frame<SIZE> {
    pub fn into_block(self) -> PhysBlock<FixedSize<SIZE>, Alignment<SIZE>> {
        unsafe { PhysBlock::new_unchecked(self.base_address(), SIZE as u64) }
    }
}

impl<const SIZE: usize> PhysBlock<FixedSize<SIZE>, Alignment<SIZE>> {
    pub fn into_frame(self) -> Frame<SIZE> {
        Frame::new(self.begin())
    }
}

impl<'a, const SIZE: usize> Page<SIZE>
where
    PageAligment: AlignMarker<SIZE>,
{
    pub fn into_block(&self) -> VirtBlock<'_, FixedSize<SIZE>, Alignment<SIZE>> {
        unsafe {
            VirtBlock::new_unchecked(VirtAddr::from_ptr(self as *const Page<SIZE>), SIZE as u64)
        }
    }
}

impl<'a, const SIZE: usize> VirtBlock<'a, FixedSize<SIZE>, Alignment<SIZE>>
where
    PageAligment: AlignMarker<SIZE>,
{
    pub unsafe fn into_page_ref(self) -> &'a Page<SIZE> {
        let ptr: *const Page<SIZE> = self.begin().as_ptr();
        unsafe { ptr.as_ref().unwrap() }
    }

    pub unsafe fn into_page_mut(self) -> &'a mut Page<SIZE> {
        let mut_ptr: *mut Page<SIZE> = self.begin().as_mut_ptr();
        unsafe { mut_ptr.as_mut().unwrap() }
    }
}

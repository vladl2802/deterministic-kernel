use core::mem::MaybeUninit;

pub trait Size: Copy {}
pub trait Align: Copy {
    fn check(addr: usize) -> bool;
}

#[derive(Debug, Clone, Copy)]
pub struct DynamicSize;

#[derive(Debug, Clone, Copy)]
pub struct FixedSize<const N: usize>;

impl Size for DynamicSize {}
impl<const N: usize> Size for FixedSize<N> {}

#[derive(Debug, Clone, Copy)]
pub struct AnyAlign;

#[derive(Debug, Clone, Copy)]
pub struct Alignment<const N: usize>;

impl Align for AnyAlign {
    fn check(_addr: usize) -> bool {
        true
    }
}

impl<const N: usize> Align for Alignment<N> {
    fn check(addr: usize) -> bool {
        addr % N == 0
    }
}

pub trait Block<Tag, Sz: Size = DynamicSize, Al: Align = AnyAlign>: Sized {
    fn byte_len(&self) -> u64;
    unsafe fn cast_state<Sz2: Size, Al2: Align>(self) -> impl Block<Tag, Sz2, Al2>;

    fn assert_fixed_len<const N: usize>(self) -> impl Block<Tag, FixedSize<N>, Al> {
        assert_eq!(self.byte_len() as usize, N);
        unsafe { Self::cast_state(self) }
    }
}

pub trait FixedBlock<Tag, const N: usize, Al: Align>: Block<Tag, FixedSize<N>, Al> {
    const BYTE_LEN: usize = N;
}

pub trait BlockAddress<Tag> {
    type Addr: Copy;
    fn begin(&self) -> Self::Addr;
    fn range(&self) -> core::ops::Range<Self::Addr>;
}

pub unsafe trait BackedBlock<Tag, Sz: Size, Al: Align>: Block<Tag, Sz, Al> {
    fn as_uninit_ptr(&self) -> *const [MaybeUninit<u8>];
    fn as_uninit_ptr_mut(&mut self) -> *mut [MaybeUninit<u8>];
}

pub unsafe trait FixedBackedBlock<Tag, const N: usize, Al: Align>:
    BackedBlock<Tag, FixedSize<N>, Al> + FixedBlock<Tag, N, Al>
{
    fn as_uninit_array_ptr(&self) -> *const [MaybeUninit<u8>; N];
    fn as_uninit_array_ptr_mut(&mut self) -> *mut [MaybeUninit<u8>; N];
}

pub trait BlockChunks<Tag, Sz: Size, Al: Align>: IntoIterator<Item = Self::Block<Sz, Al>> + Sized {
    type Block<BlSz: Size, BlAl: Align>: Block<Tag, BlSz, BlAl> + Copy;

    fn len(&self) -> usize;
    fn at(&self, index: usize) -> Self::Block<Sz, Al>;
    fn split_at(self, index: usize) -> (Self, Self);
    fn into_block(self) -> Self::Block<DynamicSize, Al>;
}

pub trait Chunkable<Tag, Sz: Size, Al: Align>: Block<Tag, Sz, Al> + Sized {
    type Chunks<ChunkSz: Size>: BlockChunks<Tag, ChunkSz, AnyAlign>;

    fn chunk_by(self, k: u64) -> Self::Chunks<DynamicSize>;
    fn chunk_by_fixed<const N: usize>(self) -> Self::Chunks<FixedSize<N>>;
}

pub trait AlignedChunkable<Tag, Sz: Size, const M: usize>:
    Chunkable<Tag, Sz, Alignment<M>>
{
    type AlignedChunks<ChunkSz: Size>: BlockChunks<Tag, ChunkSz, Alignment<M>>;

    fn chunk_by_aligned(self, k: u64) -> Self::AlignedChunks<DynamicSize>;
    fn chunk_by_fixed_aligned<const N: usize>(self) -> Self::AlignedChunks<FixedSize<N>>;
}

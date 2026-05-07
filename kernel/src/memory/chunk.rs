use core::{cell::Cell, fmt, marker, mem, ops, pin::Pin};

use arch_x86_64::{
    block::{Alignment, DynamicSize},
    frage::{L0_PAGE_SIZE, VirtBlock},
};

use crate::common::{IntrusiveRcStorage, RcStored};

use super::manager::{MappingFlags, Origin, MemoryManager};

pub type BackingBlock = VirtBlock<'static, DynamicSize, Alignment<L0_PAGE_SIZE>>;

#[derive(Debug)]
pub struct ChunkInfo {
    memory: BackingBlock,
    flags: MappingFlags,
    origin: Origin,
}

#[derive(Debug)]
pub struct OwnedChunk {
    info: mem::ManuallyDrop<ChunkInfo>,
    weak_ref_count: Cell<u32>,
    _unpin: marker::PhantomPinned,
}

#[derive(Debug)]
struct RefCountedChunkState {
    info: mem::ManuallyDrop<ChunkInfo>,
    weak_ref_count: Cell<u32>,
}

#[derive(Debug)]
pub struct RefCountedChunk(IntrusiveRcStorage<RefCountedChunkState>);

trait BorrowableChunk {
    fn ref_add(self: Pin<&Self>, diff: u32);
    fn ref_sub(self: Pin<&Self>, diff: u32);
    fn info_ref(self: Pin<&Self>) -> &ChunkInfo;
}

#[derive(Debug)]
pub struct BorrowedChunk {
    parent: *const dyn BorrowableChunk,
    weak_ref_count: Cell<u32>,
}

impl ChunkInfo {
    pub(super) fn new(memory: BackingBlock, flags: MappingFlags, origin: Origin) -> Self {
        Self {
            memory,
            flags,
            origin,
        }
    }

    pub fn memory(&self) -> &BackingBlock {
        &self.memory
    }

    pub fn flags(&self) -> MappingFlags {
        self.flags
    }

    pub fn origin(&self) -> Origin {
        self.origin
    }

    fn deallocate(self) {
        MemoryManager::unmap(self);
    }
}

impl OwnedChunk {
    pub fn new(info: ChunkInfo) -> Self {
        Self {
            info: mem::ManuallyDrop::new(info),
            weak_ref_count: Cell::new(0),
            _unpin: marker::PhantomPinned,
        }
    }

    pub fn extract_info(mut self) -> ChunkInfo {
        let info = unsafe { mem::ManuallyDrop::take(&mut self.info) };
        // Will not call a destructor that otherwise would take info second time.
        // Struct does not own any memory at that point, drop is noop here.
        mem::forget(self);
        info
    }

    pub fn info_ref(&self) -> &ChunkInfo {
        &self.info
    }

    // User must ensure that this chunk overlives borrowed one.
    // For the local borrows deref into ChunkInfo should be prefered.
    pub unsafe fn borrow(self: Pin<&Self>) -> BorrowedChunk {
        self.weak_ref_count.update(|rc| rc + 1);
        unsafe { BorrowedChunk::new(self) }
    }
}

impl Drop for OwnedChunk {
    fn drop(&mut self) {
        // If we hit drop, then we must own valid info and therefore we must unmap it.
        let info = unsafe { mem::ManuallyDrop::take(&mut self.info) };
        info.deallocate();
    }
}

impl RcStored for RefCountedChunkState {
    fn on_drop(&mut self, prev: Option<&Self>, next: Option<&Self>) {
        let neighbour = prev.or(next);
        if let Some(_) = neighbour {
            assert_eq!(
                self.weak_ref_count.get(),
                0,
                "Non zero weak ref count on non-last rc {}",
                *self.info
            );
            // Even so references were created from this object, they are still valid and this can work:
            // neighbour.weak_ref_count.update(|c| c + self.weak_ref_count.get());
            // However leaving references and deleting refcounted object doesn't seem valid.
            // Panic for now, if there would be valuable usecase, then maybe allow this.
        } else {
            assert_eq!(
                self.weak_ref_count.get(),
                0,
                "Non zero weak ref count on last rc {}",
                *self.info
            );

            // This is the last reference, so we can delete it safely.
            let info = unsafe { mem::ManuallyDrop::take(&mut self.info) };
            info.deallocate();
        }
    }
}

impl RefCountedChunk {
    pub fn new(info: ChunkInfo) -> Self {
        Self(IntrusiveRcStorage::new_unlinked(RefCountedChunkState {
            info: mem::ManuallyDrop::new(info),
            weak_ref_count: Cell::new(0),
        }))
    }

    pub fn init(self: Pin<&Self>, other: Pin<&Self>) {
        let this = unsafe { self.map_unchecked(|p| &p.0) };
        let other = unsafe { other.map_unchecked(|p| &p.0) };
        unsafe { IntrusiveRcStorage::<RefCountedChunkState>::link_to(this, other) };
    }

    // User must ensure that this chunk overlives borrowed one.
    // For the local borrows deref into ChunkInfo should be prefered.
    pub unsafe fn reference(self: Pin<&Self>) -> BorrowedChunk {
        self.0.value().weak_ref_count.update(|rc| rc + 1);
        unsafe { BorrowedChunk::new(self) }
    }
}

impl BorrowedChunk {
    // User must ensure that parent lives long enough.
    unsafe fn new<'a>(parent: Pin<&'a dyn BorrowableChunk>) -> Self {
        let parent_ref: &dyn BorrowableChunk = parent.get_ref();
        let parent_static: &(dyn BorrowableChunk + 'static) = unsafe { mem::transmute(parent_ref) };

        Self {
            parent: parent_static,
            weak_ref_count: Cell::new(0),
        }
    }

    // User must ensure that this chunk overlives borrowed one.
    // For the local borrows deref into ChunkInfo should be prefered.
    pub unsafe fn reference(self: Pin<&Self>) -> BorrowedChunk {
        unsafe { BorrowedChunk::new(self) }
    }

    // User must ensure that parent of this chunk overlives borrowed one.
    // For the local borrows deref into ChunkInfo should be prefered.
    pub unsafe fn reference_parent(&self) -> BorrowedChunk {
        BorrowedChunk {
            parent: self.parent,
            weak_ref_count: Cell::new(0),
        }
    }

    unsafe fn parent(&self) -> Pin<&dyn BorrowableChunk> {
        unsafe { Pin::new_unchecked(&*self.parent) }
    }
}

impl BorrowableChunk for OwnedChunk {
    fn ref_add(self: Pin<&Self>, diff: u32) {
        self.weak_ref_count.update(|c| c + diff);
    }

    fn ref_sub(self: Pin<&Self>, diff: u32) {
        self.weak_ref_count.update(|c| c - diff);
    }

    fn info_ref(self: Pin<&Self>) -> &ChunkInfo {
        &self.get_ref().info
    }
}

impl BorrowableChunk for RefCountedChunk {
    fn ref_add(self: Pin<&Self>, diff: u32) {
        self.0.value().weak_ref_count.update(|c| c + diff);
    }

    fn ref_sub(self: Pin<&Self>, diff: u32) {
        self.0.value().weak_ref_count.update(|c| c - diff);
    }

    fn info_ref(self: Pin<&Self>) -> &ChunkInfo {
        &self.get_ref().0.value().info
    }
}

impl BorrowableChunk for BorrowedChunk {
    fn ref_add(self: Pin<&Self>, diff: u32) {
        self.weak_ref_count.update(|c| c + diff);
    }

    fn ref_sub(self: Pin<&Self>, diff: u32) {
        self.weak_ref_count.update(|c| c - diff);
    }

    fn info_ref(self: Pin<&Self>) -> &ChunkInfo {
        unsafe { self.get_ref().parent().info_ref() }
    }
}

impl ops::Deref for OwnedChunk {
    type Target = ChunkInfo;

    fn deref(&self) -> &Self::Target {
        &self.info
    }
}

impl ops::Deref for BorrowedChunk {
    type Target = ChunkInfo;

    fn deref(&self) -> &Self::Target {
        unsafe { self.parent() }.info_ref()
    }
}

impl ops::Deref for RefCountedChunk {
    type Target = ChunkInfo;

    fn deref(&self) -> &Self::Target {
        &self.0.value().info
    }
}

impl fmt::Display for ChunkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChunkInfo {:?} (flags = {}, origin = {:?})",
            self.memory, self.flags, self.origin
        )
    }
}

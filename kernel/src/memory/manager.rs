use core::fmt;

use arch_x86_64::{
    addr::{PhysAddr, VirtAddr},
    block::{Alignment, Block, BlockAddress, DynamicSize},
    frage::{L0_PAGE_SIZE, VirtBlock},
    protocol::LinearPhysMapping,
    pte::PageTableFlags,
};
use bitflags::bitflags;

use crate::{
    common::{SingleThreadLock, StaticStructWrapper, declare_static_struct},
    memory::page_allocator::MappingHandle,
};

use super::{
    chunk::ChunkInfo,
    frame_allocator::FramePool,
    page_allocator::{BumpAllocator, PageAllocator},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Origin {
    MainSegment,
}

bitflags! {
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct MappingFlags: u8 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
        const USER = 1 << 3;
    }
}

pub trait MemorySegment {
    fn map(&self, size: usize, flags: MappingFlags) -> Option<ChunkInfo>;
    fn unmap(&self, handle: ChunkInfo);
    // TODO: maybe split into move, shrink and grow
    fn remap(
        &self,
        handle: ChunkInfo,
        new_size: usize,
        new_flags: MappingFlags,
    ) -> Option<ChunkInfo>;
}

type Lock<T> = SingleThreadLock<T>;

struct MainSegment(Lock<BumpAllocator<'static, Lock<FramePool<'static>>>>);

impl MainSegment {
    fn map_to_pte_flags(flags: MappingFlags) -> PageTableFlags {
        let mut result = PageTableFlags::PRESENT;

        if flags.contains(MappingFlags::WRITE) {
            result.insert(PageTableFlags::WRITABLE);
        }
        if flags.contains(MappingFlags::EXECUTE) {
            result.insert(PageTableFlags::EXECUTABLE);
        }
        if flags.contains(MappingFlags::USER) {
            panic!("MainSegment does not support User allocations");
        }

        result
    }

    fn handle_to_chunk(handle: MappingHandle, flags: MappingFlags) -> ChunkInfo {
        ChunkInfo::new(
            VirtBlock::<DynamicSize, Alignment<L0_PAGE_SIZE>>::new(
                handle.start,
                handle.size as u64,
            ),
            flags,
            Origin::MainSegment,
        )
    }

    fn chunk_to_handle(chunk: ChunkInfo) -> MappingHandle {
        MappingHandle {
            start: chunk.memory().begin(),
            size: chunk.memory().byte_len() as usize,
            flags: Self::map_to_pte_flags(chunk.flags()),
        }
    }
}

const HEAP_VIRT_BASE: VirtAddr = VirtAddr::new_truncate(0x0000_4000_0000_0000);

impl MainSegment {
    fn new(mapping: &'static LinearPhysMapping, first_usable_phys: PhysAddr) -> Self {
        let frame_pool = Lock::new_unlocked(FramePool::new(mapping, first_usable_phys));
        let bump = unsafe { BumpAllocator::with_current_pml4(mapping, HEAP_VIRT_BASE, frame_pool) };
        MainSegment(Lock::new_unlocked(bump))
    }
}

impl MemorySegment for MainSegment {
    fn map(&self, size: usize, flags: MappingFlags) -> Option<ChunkInfo> {
        let handle = self.0.map(size, Self::map_to_pte_flags(flags))?;
        Some(Self::handle_to_chunk(handle, flags))
    }

    fn unmap(&self, handle: ChunkInfo) {
        self.0.unmap(Self::chunk_to_handle(handle));
    }

    fn remap(
        &self,
        handle: ChunkInfo,
        new_size: usize,
        new_flags: MappingFlags,
    ) -> Option<ChunkInfo> {
        let handle = self.0.remap(
            Self::chunk_to_handle(handle),
            new_size,
            Self::map_to_pte_flags(new_flags),
        )?;
        Some(Self::handle_to_chunk(handle, new_flags))
    }
}

pub struct MemoryManagerState {
    main_segment: MainSegment,
}

declare_static_struct!(pub main_manager => MemoryManager = MemoryManagerState);
pub use main_manager::MemoryManager;

pub fn init(mapping: &'static LinearPhysMapping, first_usable_phys: PhysAddr) {
    MemoryManager::finish_init(MemoryManagerState {
        main_segment: MainSegment::new(mapping, first_usable_phys),
    });
}

impl MemoryManager {
    pub fn main_segment() -> &'static impl MemorySegment {
        &Self::get().main_segment
    }

    pub(super) fn unmap(handle: ChunkInfo) {
        match handle.origin() {
            Origin::MainSegment => Self::main_segment().unmap(handle),
        }
    }
}

impl fmt::Display for MappingFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut write_flag = |flag: MappingFlags, yes: char| -> fmt::Result {
            if self.contains(flag) {
                write!(f, "{}", yes)
            } else {
                write!(f, "-")
            }
        };

        write_flag(MappingFlags::READ, 'R')?;
        write_flag(MappingFlags::WRITE, 'W')?;
        write_flag(MappingFlags::EXECUTE, 'X')?;
        write_flag(MappingFlags::USER, 'U')?;

        Ok(())
    }
}

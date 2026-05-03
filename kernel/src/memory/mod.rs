pub mod address_space;
pub mod frame_allocator;
pub mod global_allocator;
pub mod page_allocator;

pub use address_space::{AddressSpace, MapError};
pub use frame_allocator::{FrameAllocator, MainFrameAllocator, OwnedFrame};
pub use page_allocator::{BumpAllocator, MappingHandle, MemoryManager, MainMemoryManager};

use crate::common::SingleThreadLock;
use arch_x86_64::{addr::VirtAddr, protocol::BootInfo, pte::PageTableFlags};

const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

pub fn init(boot_info: &'static BootInfo) {
    let region = &boot_info.memory_region;
    frame_allocator::init(region, boot_info.first_usable_phys);
    page_allocator::init(region);

    let heap = MainMemoryManager
        .mmap(
            HEAP_SIZE,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        )
        .expect("failed to allocate heap");
    global_allocator::init(heap.start.as_u64() as usize, HEAP_SIZE);
}

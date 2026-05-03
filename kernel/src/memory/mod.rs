pub mod address_space;
pub mod frame_allocator;
pub mod global_allocator;
pub mod page_allocator;

pub use address_space::{AddressSpace, MapError};
pub use frame_allocator::{FrameAllocator, MainFrameAllocator, OwnedFrame};
pub use page_allocator::{BumpAllocator, MappingHandle, MemoryManager};

use arch_x86_64::{addr::VirtAddr, protocol::BootInfo, pte::PageTableFlags};

const HEAP_VIRT_BASE: VirtAddr = VirtAddr::new_truncate(0x0000_4000_0000_0000);
const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

pub type MainMemoryManager = BumpAllocator<'static, MainFrameAllocator>;

pub fn init(boot_info: &'static BootInfo) -> MainMemoryManager {
    let region = &boot_info.memory_region;
    frame_allocator::init(region, boot_info.first_usable_phys);
    let mut mm =
        unsafe { BumpAllocator::with_current_pml4(region, HEAP_VIRT_BASE, MainFrameAllocator) };

    let heap = mm
        .mmap(
            HEAP_SIZE,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        )
        .expect("failed to allocate heap");
    global_allocator::init(heap.start.as_u64() as usize, HEAP_SIZE);

    mm
}

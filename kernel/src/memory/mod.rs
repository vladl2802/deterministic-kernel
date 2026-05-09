pub mod address_space;
pub mod frame_allocator;
pub mod global_allocator;
pub mod page_allocator;
pub mod manager;
pub mod chunk;

use core::mem;

use arch_x86_64::{block::BlockAddress, protocol::BootInfo};

pub use manager::{MemoryManager, MappingFlags, MemorySegment};

const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

pub fn init(boot_info: &'static BootInfo) {
    manager::init(boot_info);

    let heap = MemoryManager::main_segment()
        .map(HEAP_SIZE, MappingFlags::READ | MappingFlags::WRITE)
        .expect("failed to allocate heap");
    global_allocator::init(heap.memory().begin().as_u64() as usize, HEAP_SIZE);
    // TODO: maybe store this staticly?
    mem::forget(heap);
}

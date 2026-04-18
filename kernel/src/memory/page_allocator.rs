use arch_x86_64::{
    addr::VirtAddr,
    frage::L0_PAGE_SIZE,
    protocol::LinearPhysMapping,
    pte::PageTableFlags,
};

use super::{
    address_space::AddressSpace,
    frame_allocator::FrameAllocator,
};

pub struct MappingHandle {
    pub start: VirtAddr,
    pub size: usize,
    pub flags: PageTableFlags,
}

pub trait MemoryManager {
    fn mmap(&mut self, size: usize, flags: PageTableFlags) -> Option<MappingHandle>;
    fn munmap(&mut self, handle: MappingHandle);
}

pub struct BumpAllocator<'a> {
    addr_space: AddressSpace<'a>,
    frame_alloc: FrameAllocator<'a>,
    virt_next: VirtAddr,
}

impl<'a> BumpAllocator<'a> {
    pub fn new(
        phys_mapping: &'a LinearPhysMapping,
        mut frame_alloc: FrameAllocator<'a>,
        virt_base: VirtAddr,
    ) -> Option<Self> {
        let addr_space = AddressSpace::new(phys_mapping, &mut frame_alloc)?;
        Some(Self { addr_space, frame_alloc, virt_next: virt_base })
    }

    pub unsafe fn with_current_pml4(
        phys_mapping: &'a LinearPhysMapping,
        frame_alloc: FrameAllocator<'a>,
        virt_base: VirtAddr,
    ) -> Self {
        let addr_space = unsafe { AddressSpace::from_current(phys_mapping) };
        Self { addr_space, frame_alloc, virt_next: virt_base }
    }
}

impl MemoryManager for BumpAllocator<'_> {
    fn mmap(&mut self, size: usize, flags: PageTableFlags) -> Option<MappingHandle> {
        let page_count = size.div_ceil(L0_PAGE_SIZE);
        let start = self.virt_next;
        for i in 0..page_count {
            let virt = VirtAddr::new(start.as_u64() + (i * L0_PAGE_SIZE) as u64);
            let frame = self.frame_alloc.allocate()?;
            self.addr_space.map(virt, frame, flags, &mut self.frame_alloc).ok()?;
        }
        self.virt_next = VirtAddr::new(start.as_u64() + (page_count * L0_PAGE_SIZE) as u64);
        Some(MappingHandle { start, size, flags })
    }

    fn munmap(&mut self, handle: MappingHandle) {
        let page_count = handle.size.div_ceil(L0_PAGE_SIZE);
        for i in 0..page_count {
            let virt = VirtAddr::new(handle.start.as_u64() + (i * L0_PAGE_SIZE) as u64);
            if let Some(frame) = self.addr_space.unmap(virt) {
                self.frame_alloc.deallocate(frame);
            }
        }
    }
}

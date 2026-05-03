use arch_x86_64::{
    addr::VirtAddr, frage::L0_PAGE_SIZE, protocol::LinearPhysMapping, pte::PageTableFlags,
};

use super::{address_space::AddressSpace, frame_allocator::FrameAllocator};

#[derive(Debug, Clone, Copy)]
pub struct MappingHandle {
    pub start: VirtAddr,
    pub size: usize,
    pub flags: PageTableFlags,
}

pub trait MemoryManager {
    fn mmap(&mut self, size: usize, flags: PageTableFlags) -> Option<MappingHandle>;
    fn munmap(&mut self, handle: MappingHandle);
    // TODO: maybe split into move, shrink and grow
    fn mremap(
        &mut self,
        handle: MappingHandle,
        new_size: usize,
        new_flags: PageTableFlags,
    ) -> Option<MappingHandle>;
}

pub struct BumpAllocator<'a, A: FrameAllocator> {
    addr_space: AddressSpace<'a>,
    virt_next: VirtAddr,
    frame_alloc: A,
}

impl<'a, A: FrameAllocator> BumpAllocator<'a, A> {
    pub fn new(
        phys_mapping: &'a LinearPhysMapping,
        frame_alloc: A,
        virt_base: VirtAddr,
    ) -> Option<Self> {
        let addr_space = AddressSpace::new(phys_mapping, &frame_alloc)?;
        Some(Self {
            addr_space,
            virt_next: virt_base,
            frame_alloc,
        })
    }

    pub unsafe fn with_current_pml4(
        phys_mapping: &'a LinearPhysMapping,
        virt_base: VirtAddr,
        frame_alloc: A,
    ) -> Self {
        let addr_space = unsafe { AddressSpace::from_current(phys_mapping) };
        Self {
            addr_space,
            virt_next: virt_base,
            frame_alloc,
        }
    }
}

impl<A: FrameAllocator> MemoryManager for BumpAllocator<'_, A> {
    fn mmap(&mut self, size: usize, flags: PageTableFlags) -> Option<MappingHandle> {
        let page_count = size.div_ceil(L0_PAGE_SIZE);
        let start = self.virt_next;
        for i in 0..page_count {
            let virt = VirtAddr::new(start.as_u64() + (i * L0_PAGE_SIZE) as u64);
            let frame = self.frame_alloc.alloc()?;
            self.addr_space
                .map(virt, frame, flags, &self.frame_alloc)
                .ok()?;
        }
        self.virt_next = VirtAddr::new(start.as_u64() + (page_count * L0_PAGE_SIZE) as u64);
        Some(MappingHandle { start, size, flags })
    }

    fn munmap(&mut self, handle: MappingHandle) {
        let page_count = handle.size.div_ceil(L0_PAGE_SIZE);
        for i in 0..page_count {
            let virt = VirtAddr::new(handle.start.as_u64() + (i * L0_PAGE_SIZE) as u64);
            if let Some(frame) = self.addr_space.unmap(virt) {
                self.frame_alloc.dealloc(frame);
            }
        }
    }

    fn mremap(
        &mut self,
        handle: MappingHandle,
        new_size: usize,
        new_flags: PageTableFlags,
    ) -> Option<MappingHandle> {
        let old_page_count = handle.size.div_ceil(L0_PAGE_SIZE);
        let new_page_count = new_size.div_ceil(L0_PAGE_SIZE);
        let keep_count = old_page_count.min(new_page_count);

        if handle.flags != new_flags {
            for i in 0..keep_count {
                let virt = VirtAddr::new(handle.start.as_u64() + (i * L0_PAGE_SIZE) as u64);
                if let Some(frame) = self.addr_space.unmap(virt) {
                    self.addr_space
                        .map(virt, frame, new_flags, &self.frame_alloc)
                        .ok()?;
                }
            }
        }

        if new_page_count < old_page_count {
            for i in new_page_count..old_page_count {
                let virt = VirtAddr::new(handle.start.as_u64() + (i * L0_PAGE_SIZE) as u64);
                if let Some(frame) = self.addr_space.unmap(virt) {
                    self.frame_alloc.dealloc(frame);
                }
            }
        } else if new_page_count > old_page_count {
            let mapping_end =
                VirtAddr::new(handle.start.as_u64() + (old_page_count * L0_PAGE_SIZE) as u64);
            if mapping_end != self.virt_next {
                return None;
            }
            for i in old_page_count..new_page_count {
                let virt = VirtAddr::new(handle.start.as_u64() + (i * L0_PAGE_SIZE) as u64);
                let frame = self.frame_alloc.alloc()?;
                self.addr_space
                    .map(virt, frame, new_flags, &self.frame_alloc)
                    .ok()?;
            }
            self.virt_next =
                VirtAddr::new(handle.start.as_u64() + (new_page_count * L0_PAGE_SIZE) as u64);
        }

        Some(MappingHandle {
            start: handle.start,
            size: new_size,
            flags: new_flags,
        })
    }
}

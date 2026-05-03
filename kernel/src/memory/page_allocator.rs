use core::alloc::{Allocator, Layout};
use core::ptr;

use arch_x86_64::{
    addr::VirtAddr, frage::L0_PAGE_SIZE, protocol::LinearPhysMapping, pte::PageTableFlags,
};

use crate::common::{SingleThreadLock, StaticStructWrapper, declare_static_struct};

use super::{
    address_space::AddressSpace,
    frame_allocator::{FrameAllocator, MainFrameAllocator},
};

#[derive(Debug, Clone, Copy)]
pub struct MappingHandle {
    pub start: VirtAddr,
    pub size: usize,
    pub flags: PageTableFlags,
}

pub trait MemoryManager {
    fn mmap(&self, size: usize, flags: PageTableFlags) -> Option<MappingHandle>;
    fn munmap(&self, handle: MappingHandle);
    // TODO: maybe split into move, shrink and grow
    fn mremap(
        &self,
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

impl<A: FrameAllocator> MemoryManager for SingleThreadLock<BumpAllocator<'_, A>> {
    fn mmap(&self, size: usize, flags: PageTableFlags) -> Option<MappingHandle> {
        self.with_lock(|mm| mm.mmap(size, flags))
    }

    fn munmap(&self, handle: MappingHandle) {
        self.with_lock(|mm| mm.munmap(handle))
    }

    fn mremap(
        &self,
        handle: MappingHandle,
        new_size: usize,
        new_flags: PageTableFlags,
    ) -> Option<MappingHandle> {
        self.with_lock(|mm| mm.mremap(handle, new_size, new_flags))
    }
}

unsafe impl<A: FrameAllocator> Allocator for SingleThreadLock<BumpAllocator<'_, A>> {
    fn allocate(&self, layout: Layout) -> Result<ptr::NonNull<[u8]>, core::alloc::AllocError> {
        self.with_lock(|mm| {
            let align = layout.align();
            let aligned = mm.virt_next.align_up(align as u64);
            mm.virt_next = aligned;
            let handle = mm
                .mmap(
                    layout.size(),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                )
                .ok_or(core::alloc::AllocError)?;
            let ptr = handle.start.as_u64() as *mut u8;
            let slice = core::ptr::slice_from_raw_parts_mut(ptr, layout.size());
            Ok(unsafe { ptr::NonNull::new_unchecked(slice) })
        })
    }

    unsafe fn deallocate(&self, ptr: ptr::NonNull<u8>, layout: Layout) {
        let handle = MappingHandle {
            start: VirtAddr::new(ptr.as_ptr() as u64),
            size: layout.size(),
            flags: PageTableFlags::empty(),
        };
        self.with_lock(|mm| mm.munmap(handle));
    }
}

impl<T: StaticStructWrapper<UnderlyingT: MemoryManager>> MemoryManager for T {
    fn mmap(&self, size: usize, flags: PageTableFlags) -> Option<MappingHandle> {
        Self::get().mmap(size, flags)
    }

    fn munmap(&self, handle: MappingHandle) {
        Self::get().munmap(handle);
    }

    fn mremap(
        &self,
        handle: MappingHandle,
        new_size: usize,
        new_flags: PageTableFlags,
    ) -> Option<MappingHandle> {
        Self::get().mremap(handle, new_size, new_flags)
    }
}

declare_static_struct!(pub main_memory_manager => MainMemoryManager = SingleThreadLock<BumpAllocator<'static, MainFrameAllocator>>);
pub use main_memory_manager::MainMemoryManager;

const HEAP_VIRT_BASE: VirtAddr = VirtAddr::new_truncate(0x0000_4000_0000_0000);

pub fn init(mapping: &'static LinearPhysMapping) {
    MainMemoryManager::finish_init(SingleThreadLock::new_unlocked(unsafe {
        BumpAllocator::with_current_pml4(mapping, HEAP_VIRT_BASE, MainFrameAllocator)
    }));
}

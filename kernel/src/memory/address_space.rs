use arch_x86_64::{
    addr::{PhysAddr, VirtAddr},
    frage::L0Frame,
    instructions::tlb,
    protocol::LinearPhysMapping,
    pte::{PageTable, PageTableEntry, PageTableFlags, PageTableLevel},
    registers::Cr3,
};

use super::frame_allocator::{FrameAllocator, OwnedFrame};

pub struct AddressSpace<'a> {
    phys_mapping: &'a LinearPhysMapping,
    pml4: OwnedFrame,
}

pub enum MapError {
    AllocFailed,
    AlreadyMapped,
}

impl<'a> AddressSpace<'a> {
    pub fn new(phys_mapping: &'a LinearPhysMapping, pt_alloc: &mut FrameAllocator) -> Option<Self> {
        let pml4 = pt_alloc.allocate()?;
        PageTable::new_non_present(unsafe { &mut *phys_mapping.frame_to_ptr(pml4.phys()) });
        Some(Self { phys_mapping, pml4 })
    }

    pub unsafe fn from_current(phys_mapping: &'a LinearPhysMapping) -> Self {
        let pml4 = OwnedFrame::from_raw(L0Frame::new(Cr3::read().pml4_phys()));
        Self { phys_mapping, pml4 }
    }

    pub fn map(
        &mut self,
        virt: VirtAddr,
        frame: OwnedFrame,
        flags: PageTableFlags,
        pt_alloc: &mut FrameAllocator,
    ) -> Result<(), MapError> {
        let pte = unsafe {
            walk_or_create(self.phys_mapping, self.pml4.phys(), virt, flags, pt_alloc)
                .ok_or(MapError::AllocFailed)?
        };
        let pte = unsafe { &mut *pte };
        if pte.flags().is_present() {
            return Err(MapError::AlreadyMapped);
        }
        *pte = PageTableEntry::new(frame.phys().base_address(), flags);
        Ok(())
    }

    pub fn unmap(&mut self, virt: VirtAddr) -> Option<OwnedFrame> {
        let pte = unsafe { walk_existing(self.phys_mapping, self.pml4.phys(), virt)? };
        let pte = unsafe { &mut *pte };
        let phys = pte.address();
        *pte = PageTableEntry::non_present();
        tlb::flush(virt);
        Some(OwnedFrame::from_raw(L0Frame::new(phys)))
    }

    pub fn pml4_phys(&self) -> PhysAddr {
        self.pml4.phys().base_address()
    }
}

unsafe fn walk_or_create(
    mapping: &LinearPhysMapping,
    pml4: L0Frame,
    virt: VirtAddr,
    flags: PageTableFlags,
    pt_alloc: &mut FrameAllocator,
) -> Option<*mut PageTableEntry> {
    let access = flags & PageTableFlags::ACCESS_FLAGS;

    let mut frame = pml4;
    let mut level = PageTableLevel::Four;
    loop {
        let table = unsafe { PageTable::existing_mut(&mut *mapping.frame_to_ptr(frame)) };
        let idx = usize::from(virt.page_table_index(level));
        match level.next_lower_level() {
            None => return Some(&mut table[idx]),
            Some(next_level) => {
                if !table[idx].flags().is_present() {
                    let child = pt_alloc.allocate()?;
                    let child_phys = child.phys();
                    PageTable::new_non_present(unsafe { &mut *mapping.frame_to_ptr(child_phys) });
                    table[idx] =
                        PageTableEntry::new(child_phys.base_address(), PageTableFlags::PRESENT | access);
                } else {
                    let flags = table[idx].flags();
                    table[idx].set_flags(flags | access);
                }
                frame = L0Frame::new(table[idx].address());
                level = next_level;
            }
        }
    }
}

unsafe fn walk_existing(
    mapping: &LinearPhysMapping,
    pml4: L0Frame,
    virt: VirtAddr,
) -> Option<*mut PageTableEntry> {
    let mut frame = pml4;
    let mut level = PageTableLevel::Four;
    loop {
        let table = unsafe { PageTable::existing_mut(&mut *mapping.frame_to_ptr(frame)) };
        let idx = usize::from(virt.page_table_index(level));
        match level.next_lower_level() {
            None => return Some(&mut table[idx]),
            Some(next_level) => {
                if !table[idx].flags().is_present() {
                    return None;
                }
                frame = L0Frame::new(table[idx].address());
                level = next_level;
            }
        }
    }
}

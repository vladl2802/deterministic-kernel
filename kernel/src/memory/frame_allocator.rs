use core::{mem::{self, ManuallyDrop}, ptr};

use arch_x86_64::{addr::PhysAddr, frage::{L0Frame, L0Page}, protocol::LinearPhysMapping};

pub struct OwnedFrame {
    frame: L0Frame,
}

impl OwnedFrame {
    pub(super) fn from_raw(frame: L0Frame) -> Self {
        Self { frame }
    }

    pub fn phys(&self) -> L0Frame {
        self.frame
    }

    pub unsafe fn as_page_ptr(&self, mapping: &LinearPhysMapping) -> *mut L0Page {
        mapping.frame_to_ptr(self.frame)
    }
}

union FrameInfo {
    page: ManuallyDrop<L0Page>,
    info: u64,
}

impl FrameInfo {
    unsafe fn from_free_page_mut(page: &mut L0Page) -> &mut FrameInfo {
        unsafe { &mut *(ptr::from_mut(page) as *mut FrameInfo) }
    }

    unsafe fn into_page_mut(&mut self) -> &mut L0Page {
        unsafe { &mut *(ptr::from_mut(self) as *mut L0Page) }
    }

    fn get_info(&self) -> u64 {
        unsafe { self.info }
    }

    fn set_info(&mut self, info: u64) {
        self.info = info
    }
}

pub struct FrameAllocator<'a> {
    mapping: &'a LinearPhysMapping,
    free_count: u64,
    first_free: Option<u64>,
}

impl<'a> FrameAllocator<'a> {
    pub fn new(mapping: &'a LinearPhysMapping, first_usable_phys: PhysAddr) -> Self {
        let free_count = mapping.frame_count();
        let first_free = (first_usable_phys - mapping.frame_from_index(0).base_address()) / L0Page::SIZE;
        let first_free = if first_free >= free_count {
            None
        } else {
            Some(first_free)
        };

        Self {
            mapping,
            free_count,
            first_free,
        }
    }

    fn get_next_free(info: &FrameInfo, idx: u64) -> u64 {
        (info.get_info() ^ idx) + 1
    }

    fn set_next_free(info: &mut FrameInfo, idx: u64, next_free: u64) {
        info.set_info((next_free -  1) ^ idx);
    }

    pub fn allocate(&mut self) -> Option<OwnedFrame> {
        let idx = self.first_free?;
        let frame = self.mapping.frame_from_index(idx);
        let page = self.mapping.frame_to_ptr(frame);

        let info = unsafe { FrameInfo::from_free_page_mut(&mut *page) };
        let next_free = Self::get_next_free(info, idx);
        self.first_free = if next_free == self.mapping.frame_count() {
            None
        } else {
            Some(next_free)
        };

        self.free_count -= 1;

        Some(OwnedFrame { frame })
    }

    pub fn deallocate(&mut self, frame: OwnedFrame) {
        let frame = frame.frame;
        let idx = self.mapping.frame_to_index(frame);
        let page = self.mapping.frame_to_ptr(frame);

        let info = unsafe { FrameInfo::from_free_page_mut(&mut *page) };
        let next_free = mem::replace(&mut self.first_free, Some(idx));
        let next_free = next_free.unwrap_or(self.mapping.frame_count());
        Self::set_next_free(info, idx, next_free);

        self.free_count += 1;

        self.first_free = Some(idx);
    }
}

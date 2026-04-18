use core::{fmt, ops::Range};

use crate::{
    addr::{PhysAddr, VirtAddr},
    frage::{L0Frame, L0Page},
};

pub const HIT_PORT: u16 = 0xF0;

#[derive(Clone, Copy, Debug)]
// TODO: Should become #[non_exhaustive]
pub struct BootInfo {
    pub logging_port: u16,
    pub event_port: u16,
    pub memory_region: LinearPhysMapping,
    pub first_usable_phys: PhysAddr,
    pub salt: u64,
}

#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum KernelEvent {
    Panic = 0,
    // OutOfMemory = 1,
}

impl KernelEvent {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(KernelEvent::Panic),
            _ => None,
        }
    }
}

impl fmt::Display for KernelEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelEvent::Panic => f.write_str("Panic"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinearPhysMapping {
    phys_base: PhysAddr,
    virt_base: VirtAddr,
    frame_count: u64,
}

impl LinearPhysMapping {
    pub fn new(region: Range<PhysAddr>, virt_base: VirtAddr) -> Option<LinearPhysMapping> {
        assert!(region.start.is_aligned(L0Page::SIZE));
        assert!(region.end.is_aligned(L0Page::SIZE));
        assert!(virt_base.is_aligned(L0Page::SIZE));

        let length = region.end - region.start;
        VirtAddr::try_new(virt_base.as_u64() + length).ok()?;

        Some(LinearPhysMapping {
            phys_base: region.start,
            virt_base,
            frame_count: length / L0Page::SIZE,
        })
    }

    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    pub fn frame_to_index(&self, frame: L0Frame) -> u64 {
        let index = (frame.base_address() - self.phys_base) / L0Page::SIZE;
        assert!(index < self.frame_count);
        index
    }

    pub fn frame_from_index(&self, index: u64) -> L0Frame {
        assert!(index < self.frame_count);
        L0Frame::new(self.phys_base + index * L0Frame::SIZE)
    }

    pub fn frame_to_ptr(&self, frame: L0Frame) -> *mut L0Page {
        let page_base = self.virt_base + (frame.base_address() - self.phys_base);
        page_base.as_mut_ptr()
    }

    pub fn frame_from_ptr(&self, page: *mut L0Page) -> L0Frame {
        let frame_base = self.phys_base + (VirtAddr::from_ptr(page) - self.virt_base);
        L0Frame::new(frame_base)
    }
}

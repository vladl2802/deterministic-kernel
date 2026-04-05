use core::{fmt, ops::Range};

use crate::{
    addr::{PhysAddr, VirtAddr},
    frage::L0Page,
};

pub const HIT_PORT: u16 = 0xF0;

#[derive(Clone, Copy, Debug)]
// TODO: Should become #[non_exhaustive]
pub struct BootInfo<'a> {
    pub logging_port: u16,
    pub event_port: u16,
    pub memory_regions: &'a [LinearPhysMapping],
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
            _ => None
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearPhysMapping {
    region: Range<PhysAddr>,
    virt_base: VirtAddr,
}

impl LinearPhysMapping {
    pub fn new(region: Range<PhysAddr>, virt_base: VirtAddr) -> Option<LinearPhysMapping> {
        assert!(region.start.is_aligned(L0Page::SIZE));
        assert!(region.end.is_aligned(L0Page::SIZE));
        assert!(virt_base.is_aligned(L0Page::SIZE));

        let length = region.start - region.end;
        VirtAddr::try_new(virt_base.as_u64() + length).ok()?;

        Some(LinearPhysMapping { region, virt_base })
    }
}

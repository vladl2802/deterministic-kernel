use core::ops::Range;

use crate::addr::PhysAddr;

#[derive(Clone, Copy, Debug)]
// TODO: Should become #[non_exhaustive]
pub struct BootInfo<'a> {
    pub logging_port: u16,
    pub memory_regions: &'a [MemoryRegion],
    pub salt: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    begin: PhysAddr,
    end: PhysAddr,
}

impl MemoryRegion {
    pub fn empty() -> Self {
        Self {begin: PhysAddr::zero(), end: PhysAddr::zero()}
    }

    pub fn new(begin: PhysAddr, end: PhysAddr) -> Self {
        Self {begin, end}
    }

    pub fn from_begin_len(begin: PhysAddr, len: u64) -> Self {
        Self::new(begin, PhysAddr::new(begin.as_u64() + len))
    }

    pub fn from_range(range: Range<PhysAddr>) -> Self {
        Self {begin: range.start, end: range.end}
    }

    pub fn into_range(self) -> Range<PhysAddr> {
        Range { start: self.begin, end: self.end }
    }
}

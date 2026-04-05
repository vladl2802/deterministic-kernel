use core::ops::Range;

use crate::{
    addr::{PhysAddr, VirtAddr},
    frage::L0Page,
};

pub const HIT_PORT: u16 = 0xF0;

#[derive(Clone, Copy, Debug)]
// TODO: Should become #[non_exhaustive]
pub struct BootInfo<'a> {
    pub logging_port: u16,
    pub memory_regions: &'a [LinearPhysMapping],
    pub salt: u64,
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

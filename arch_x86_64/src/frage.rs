use crate::pte::{PAGE_OFFSET_BITS, PAGE_TABLE_INDEX_BITS};

use core::mem::MaybeUninit;

use common::{align_marker::AlignMarker, define_align};

pub struct PageAligment;

define_align!(AlignL0, PageAligment, 0x1000, L0_PAGE_SIZE);
define_align!(AlignL1, PageAligment, 0x200000, L1_HUGE_PAGE_SIZE);
// AlignL2 (and L2 pages) cannot be expressed as aligned to 1<<30 slice because aligment is limited to <= 1<<29
// But it doesn't seem usefull anyways

pub struct Page<const SIZE: usize>
where
    PageAligment: AlignMarker<SIZE>,
{
    memory: [MaybeUninit<u8>; SIZE],
    _align: <PageAligment as AlignMarker<SIZE>>::Marker,
}

impl<const SIZE: usize> Page<SIZE>
where
    PageAligment: AlignMarker<SIZE>,
{
    pub const SIZE: u64 = SIZE as u64;

    pub fn bytes_ref(&self) -> &[MaybeUninit<u8>; SIZE] {
        &self.memory
    }

    pub fn bytes_mut(&mut self) -> &mut [MaybeUninit<u8>; SIZE] {
        &mut self.memory
    }
}

pub type L0Page = Page<L0_PAGE_SIZE>;
pub type L1HugePage = Page<L1_HUGE_PAGE_SIZE>;

pub const L0_PAGE_SIZE: usize = 1 << PAGE_OFFSET_BITS; // 4KiB
pub const L1_HUGE_PAGE_SIZE: usize = L0_PAGE_SIZE << PAGE_TABLE_INDEX_BITS; // 2MiB

use core::{
    fmt,
    mem::MaybeUninit,
    ops::{Index, IndexMut},
};

use bitflags::bitflags;

use crate::{
    addr::PhysAddr,
    align_marker::AlignMarker,
    define_align,
};

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

#[repr(transparent)]
pub struct PageTable([PageTableEntry; PAGE_TABLE_ENTRY_COUNT]);

impl PageTable {
    pub fn new_non_present(page: &mut L0Page) -> &mut Self {
        let uninit = Self::uninit_mut(page);
        uninit.iter_mut().for_each(|pte| {
            pte.write(PageTableEntry::non_present());
        });
        unsafe { Self::existing_mut(page) }
    }

    pub unsafe fn existing_ref(page: &L0Page) -> &Self {
        let ptes = unsafe { Self::uninit_ref(page).assume_init_ref() };
        unsafe { &*(ptes.as_ptr().cast()) }
    }

    pub unsafe fn existing_mut(page: &mut L0Page) -> &mut Self {
        let ptes = unsafe { Self::uninit_mut(page).assume_init_mut() };
        unsafe { &mut *(ptes.as_mut_ptr().cast()) }
    }

    fn uninit_mut(page: &mut L0Page) -> &mut [MaybeUninit<PageTableEntry>; PAGE_TABLE_ENTRY_COUNT] {
        unsafe { &mut *page.bytes_mut().as_mut_ptr().cast() }
    }

    fn uninit_ref(page: &L0Page) -> &[MaybeUninit<PageTableEntry>; PAGE_TABLE_ENTRY_COUNT] {
        unsafe { &*page.bytes_ref().as_ptr().cast() }
    }
}

impl Index<usize> for PageTable {
    type Output = PageTableEntry;

    fn index(&self, index: usize) -> &Self::Output {
        self.0.index(index)
    }
}

impl IndexMut<usize> for PageTable {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.0.index_mut(index)
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    const ADDRESS_MASK: u64 = ((1 << PHYS_ADDRESS_BITS) - 1) & !((1 << PAGE_OFFSET_BITS) - 1);
    const FLAGS_MASK: u64 = !Self::ADDRESS_MASK;

    pub fn new(address: PhysAddr, flags: PageTableFlags) -> Self {
        Self(address.as_u64() | (flags ^ PageTableFlags::EXECUTABLE).bits())
    }

    pub fn non_present() -> Self {
        Self(0)
    }

    pub fn address(&self) -> PhysAddr {
        // SAFETY: Address mask ensures that 52..64 are 0.
        unsafe { PhysAddr::new_unsafe(self.0 & Self::ADDRESS_MASK) }
    }

    pub fn flags(&self) -> PageTableFlags {
        let flags = PageTableFlags::from_bits_retain(self.0 & Self::FLAGS_MASK);
        flags ^ PageTableFlags::EXECUTABLE
    }

    pub fn set_flags(&mut self, flags: PageTableFlags) {
        self.0 = self.address().as_u64() | (flags ^ PageTableFlags::EXECUTABLE).bits();
    }
}

impl fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.flags().is_present() {
            write!(f, "address={:x} flags={}", self.address(), self.flags())
        } else {
            write!(f, "<non-present>")
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    pub struct PageTableFlags: u64 {
        const PRESENT = 1 << 0;
        const WRITABLE = 1 << 1;
        const USER = 1 << 2;
        const WRITE_THROUGH = 1 << 3;
        const NO_CACHE = 1 << 4;
        const ACCESSED = 1 << 5;
        const DIRTY = 1 << 6;
        const HUGE = 1 << 7;
        const GLOBAL = 1 << 8;

        const AVAILABLE_0 = 1 << 9;
        const AVAILABLE_1 = 1 << 10;
        const AVAILABLE_2 = 1 << 11;

        const EXECUTABLE = 1 << 63;
    }
}

macro_rules! derive_flags_checker {
    ($fn_name:ident, $flag:ident) => {
        impl PageTableFlags {
            pub fn $fn_name(&self) -> bool {
                self.contains(PageTableFlags::$flag)
            }
        }
    };
}
derive_flags_checker!(is_user, USER);
derive_flags_checker!(is_present, PRESENT);
derive_flags_checker!(is_writable, WRITABLE);
derive_flags_checker!(is_executable, EXECUTABLE);
derive_flags_checker!(is_dirty, DIRTY);
derive_flags_checker!(is_huge, HUGE);

impl fmt::Debug for PageTableFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:b}", (*self ^ Self::EXECUTABLE).bits())
    }
}

impl fmt::Display for PageTableFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut write_flag = |flag: PageTableFlags, yes: char| -> fmt::Result {
            if self.contains(flag) {
                write!(f, "{}", yes)
            } else {
                write!(f, "-")
            }
        };

        write_flag(PageTableFlags::PRESENT, 'P')?;
        write_flag(PageTableFlags::USER, 'U')?;
        write_flag(PageTableFlags::WRITABLE, 'W')?;
        write_flag(PageTableFlags::EXECUTABLE, 'X')?;
        write_flag(PageTableFlags::HUGE, 'H')?;
        write_flag(PageTableFlags::WRITE_THROUGH, 'T')?;
        write_flag(PageTableFlags::NO_CACHE, 'C')?;
        write_flag(PageTableFlags::GLOBAL, 'G')?;
        write_flag(PageTableFlags::AVAILABLE_0, '0')?;
        write_flag(PageTableFlags::AVAILABLE_1, '1')?;
        write_flag(PageTableFlags::AVAILABLE_2, '2')?;
        write_flag(PageTableFlags::ACCESSED, 'A')?;
        write_flag(PageTableFlags::DIRTY, 'D')?;

        Ok(())
    }
}

const PHYS_ADDRESS_BITS: usize = 52;

const PAGE_OFFSET_BITS: usize = 12;
const PAGE_TABLE_INDEX_BITS: usize = 9;
pub const PAGE_TABLE_ENTRY_COUNT: usize = 1 << PAGE_TABLE_INDEX_BITS;

pub const L0_PAGE_SIZE: usize = 1 << PAGE_OFFSET_BITS; // 4KiB
pub const L1_HUGE_PAGE_SIZE: usize = L0_PAGE_SIZE << PAGE_TABLE_INDEX_BITS; // 2MiB

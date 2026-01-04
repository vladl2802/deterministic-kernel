use core::fmt;

use bitflags::bitflags;

pub type PageTable = [PageTableEntry; PAGE_TABLE_ENTRY_COUNT];

#[derive(Clone, Copy, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct PageTableEntry(usize);

bitflags! {
    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    pub struct PageTableFlags: usize {
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

impl PageTableEntry {
    const ADDRESS_MASK: usize = ((1 << PHYS_ADDRESS_BITS) - 1) & !((1 << PAGE_OFFSET_BITS) - 1);
    const FLAGS_MASK: usize = !Self::ADDRESS_MASK;

    pub fn new(address: usize, flags: PageTableFlags) -> Self {
        Self((address & Self::ADDRESS_MASK) | (flags ^ PageTableFlags::EXECUTABLE).bits())
    }

    pub fn non_present() -> Self {
        Self(0)
    }

    pub fn address(&self) -> usize {
        self.0 & Self::ADDRESS_MASK
    }

    pub fn flags(&self) -> PageTableFlags {
        let flags = PageTableFlags::from_bits_retain(self.0 & Self::FLAGS_MASK);
        flags ^ PageTableFlags::EXECUTABLE
    }

    pub fn set_flags(&mut self, flags: PageTableFlags) {
        self.0 = self.address() | (flags ^ PageTableFlags::EXECUTABLE).bits();
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

impl fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.flags().is_present() {
            write!(f, "address={:x} flags={}", self.address(), self.flags())
        } else {
            write!(f, "<non-present>")
        }
    }
}

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

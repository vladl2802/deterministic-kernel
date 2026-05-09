pub use x86_64::registers::*;

use crate::addr::PhysAddr;

pub struct Cr3(PhysAddr);

impl Cr3 {
    pub fn read() -> Self {
        let val: u64;
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) val) };
        Self(PhysAddr::new(val & !0xFFF))
    }

    pub unsafe fn write(self) {
        unsafe { core::arch::asm!("mov cr3, {}", in(reg) self.0.as_u64()) };
    }

    pub fn pml4_phys(&self) -> PhysAddr {
        self.0
    }

    pub fn from_pml4(phys: PhysAddr) -> Self {
        Self(phys)
    }
}

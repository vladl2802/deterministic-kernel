#![no_std]

pub mod instructions {
    pub use x86_64::instructions::*;

    pub unsafe fn rdtsc() -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }
}

pub mod protocol;
pub mod pte;

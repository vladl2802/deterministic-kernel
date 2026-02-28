#![no_std]
// features
#![feature(align_to_uninit_mut)]

pub mod instructions {
    pub use x86_64::instructions::*;

    pub unsafe fn rdtsc() -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }
}

pub use x86_64::addr;

pub mod protocol;
pub mod pte;
pub mod frage;

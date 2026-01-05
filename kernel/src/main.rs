#![no_std]
#![no_main]

use core;

unsafe fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

#[panic_handler]
#[inline(never)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { halt() }
}

#[inline(never)]
fn kernel_main() -> ! {
    unsafe {
        core::arch::asm!("
            mov dx, 0x3f8
            mov al, {byte}
            out dx, al
            ",
            byte = in(reg_byte) b'A'
        )
    }

    unsafe { halt() }
}

#[unsafe(no_mangle)]
#[allow(unused)]
#[inline(never)]
pub extern "C" fn _start() -> ! {
    unsafe {
        core::arch::asm!("
            call {main}
            ",
            main = sym kernel_main,
            options(noreturn)
        )
    }
}

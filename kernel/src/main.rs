#![no_std]
#![no_main]

use core;

use arch_x86_64::instructions;

unsafe fn halt() -> ! {
    loop {
        instructions::hlt()
    }
}

#[panic_handler]
#[inline(never)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { halt() }
}

#[inline(never)]
fn kernel_main() -> ! {
    let mut port = instructions::port::Port::new(0x3f8);
    unsafe { port.write(b'A') }

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

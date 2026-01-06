#![no_std]
#![no_main]

mod logging;

use core;

use arch_x86_64::instructions;
use log::{error, debug};

unsafe fn halt() -> ! {
    loop {
        instructions::hlt()
    }
}

#[panic_handler]
#[inline(never)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    error!("PANIC");
    unsafe { halt() }
}

fn init() {
    logging::init();
}

#[inline(never)]
fn kernel_main() -> ! {
    init();

    let mut port = instructions::port::Port::new(0x3f8);
    unsafe { port.write(b'A') }
    debug!("first log is HERE!");
    unsafe { port.write(b'B') }

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

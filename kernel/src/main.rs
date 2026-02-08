#![no_std]
#![no_main]

mod logging;

use core;

use arch_x86_64::{instructions, protocol::BootInfo};
use log::{info, error, debug};

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

fn init(boot_info: &'static BootInfo) {
    logging::init(boot_info.logging_port);

    info!("kernel run salt is: {:X}", boot_info.salt);
}

#[inline(never)]
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    init(boot_info);

    let mut port = instructions::port::Port::new(0x3f8);
    unsafe { port.write(b'A') }
    debug!("first log is HERE!");
    unsafe { port.write(b'B') }

    unsafe { halt() }
}

#[unsafe(no_mangle)]
#[allow(unused)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    // hypervisor passes BootInfo pointer in RDI
    core::arch::naked_asm!("
        call {main}
        ",
        main = sym kernel_main
    )
}

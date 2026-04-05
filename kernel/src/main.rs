#![no_std]
#![no_main]

mod common;
mod event;
mod logging;

use core;

use arch_x86_64::protocol::BootInfo;
use log::{debug, error, info};

#[panic_handler]
#[inline(never)]
fn panic(info: &core::panic::PanicInfo) -> ! {
    error!("PANIC: {info}");
    event::send(event::KernelEvent::Panic);
    unsafe { common::halt() }
}

fn init(boot_info: &'static BootInfo) {
    logging::init(boot_info.logging_port);
    event::init(boot_info.event_port);

    info!("kernel run salt is: {:X}", boot_info.salt);
}

#[inline(never)]
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    init(boot_info);

    common::hit(b'A');
    debug!("first log is HERE!");
    common::hit(b'B');

    panic!("I want to panic");

    unsafe { common::halt() }
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

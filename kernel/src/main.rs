#![no_std]
#![no_main]

#![feature(alloc_error_handler)]

extern crate alloc;

mod common;
mod event;
mod logging;
mod memory;

use core;

use alloc::vec::Vec;
use arch_x86_64::{protocol::BootInfo, pte::PageTableFlags};
use log::{debug, error, info};
use memory::{BumpAllocator, MemoryManager};

#[panic_handler]
#[inline(never)]
fn panic(info: &core::panic::PanicInfo) -> ! {
    error!("PANIC: {info}");
    event::send(event::KernelEvent::Panic);
    unsafe { common::halt() }
}

fn init(boot_info: &'static BootInfo) -> BumpAllocator<'static> {
    logging::init(boot_info.logging_port);
    event::init(boot_info.event_port);
    memory::init(boot_info)
}

#[inline(never)]
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    let mut mm = init(boot_info);

    info!("inited with boot_info = {:?}", boot_info);
    info!("kernel run salt is: {:X}", boot_info.salt);

    common::hit(b'A');
    debug!("first log is HERE!");
    common::hit(b'B');

    let handle = mm
        .mmap(4096, PageTableFlags::PRESENT | PageTableFlags::WRITABLE)
        .unwrap();
    unsafe { handle.start.as_mut_ptr::<u8>().write(0xAB) };
    let val = unsafe { handle.start.as_ptr::<u8>().read() };
    assert_eq!(val, 0xAB);
    info!("memory manager ok: {:#x}", val);
    mm.munmap(handle);

    let mut vec = Vec::with_capacity(10);
    for _ in 0..20 {
        vec.push(1);
    }
    info!("len = {}, addr = {:p}", vec.len(), vec.as_ptr());

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

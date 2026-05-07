#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(abi_x86_interrupt)]
#![feature(allocator_api)]

extern crate alloc;

mod common;
mod event;
mod gdt;
mod interrupts;
mod logging;
mod memory;
mod process;
mod tss;

use alloc::vec::Vec;
use core;

use log::{debug, error, info};
use memory::{MemoryManager, MemorySegment};
use arch_x86_64::{block::BlockAddress, protocol::BootInfo};

use crate::memory::MappingFlags;

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
    memory::init(boot_info);
    let tss = tss::init(MemoryManager::main_segment());
    gdt::init(tss);
    interrupts::init();
    process::init();
}

fn task_a() -> ! {
    let mut i: u64 = 0;
    while i < 100 {
        info!("task_a: {i}");
        i += 1;
    }
    process::syscall::exit()
}

fn task_b() -> ! {
    let mut i: u64 = 0;
    loop {
        info!("task_b: {i}");
        i += 1;
    }
}

#[inline(never)]
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    init(boot_info);

    info!("inited with boot_info = {:?}", boot_info);
    info!("kernel run salt is: {:X}", boot_info.salt);

    process::spawn(task_a, MemoryManager::main_segment());
    process::spawn(task_b, MemoryManager::main_segment());

    common::hit(b'A');
    debug!("first log is HERE!");
    common::hit(b'B');

    let handle = MemoryManager::main_segment()
        .map(4096, MappingFlags::WRITE)
        .unwrap();
    unsafe { handle.memory().begin().as_mut_ptr::<u8>().write(0xAB) };
    let val = unsafe { handle.memory().begin().as_ptr::<u8>().read() };
    assert_eq!(val, 0xAB);
    info!("memory manager ok: {:#x}", val);
    MemoryManager::main_segment().unmap(handle);

    let mut vec = Vec::with_capacity(10);
    for _ in 0..20 {
        vec.push(1);
    }
    info!("len = {}, addr = {:p}", vec.len(), vec.as_ptr());

    process::run()
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

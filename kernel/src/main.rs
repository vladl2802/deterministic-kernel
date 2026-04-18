#![no_std]
#![no_main]

mod common;
mod event;
mod logging;
mod memory;

use core;

use arch_x86_64::{addr::VirtAddr, protocol::BootInfo, pte::PageTableFlags};
use log::{debug, error, info};
use memory::{BumpAllocator, FrameAllocator, MemoryManager};

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

    info!("inited with boot_info = {:?}", boot_info);

    common::hit(b'A');
    debug!("first log is HERE!");
    common::hit(b'B');

    let region = &boot_info.memory_region;
    let frame_alloc = FrameAllocator::new(region, boot_info.first_usable_phys);
    let mut mm = unsafe {
        BumpAllocator::with_current_pml4(region, frame_alloc, VirtAddr::new(0x0000_4000_0000_0000))
    };

    let handle = mm
        .mmap(4096, PageTableFlags::PRESENT | PageTableFlags::WRITABLE)
        .unwrap();
    unsafe { handle.start.as_mut_ptr::<u8>().write(0xAB) };
    let val = unsafe { handle.start.as_ptr::<u8>().read() };
    assert_eq!(val, 0xAB);
    info!("memory manager ok: {:#x}", val);
    mm.munmap(handle);

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

mod context;
mod scheduler;
pub mod syscall;
mod table;
mod task;
pub mod timer;

use arch_x86_64::instructions::interrupts;
use crate::{common, memory::MemoryManager};

pub use task::TaskId;

pub fn init() {
    scheduler::init();
    timer::init();
}

pub fn spawn(entry: fn() -> !, mm: &impl MemoryManager) -> TaskId {
    scheduler::spawn(entry, mm)
}

pub fn run() -> ! {
    interrupts::enable();
    // We are abondoning the kernel boot stack here.
    loop {
        unsafe { common::halt() };
    }
}

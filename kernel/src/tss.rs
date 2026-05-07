use core::mem;

use arch_x86_64::{addr::VirtAddr, block::BlockAddress, structures::tss::TaskStateSegment};

use crate::{
    common::LateInit,
    memory::{MappingFlags, MemorySegment},
};

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
// TODO: this is actually shouldn't be needed. ring0 switch stack will be used, when proper userspace will be implemented.
pub const SYSCALL_IST_INDEX: u16 = 1;
const DOUBLE_FAULT_STACK_SIZE: usize = 4096 * 5;
const RING0_STACK_SIZE: usize = 4096 * 5;

static TSS: LateInit<TaskStateSegment> = LateInit::new();

pub fn init(mm: &impl MemorySegment) -> &'static TaskStateSegment {
    let df_stack = mm
        .map(DOUBLE_FAULT_STACK_SIZE, MappingFlags::WRITE)
        .expect("failed to allocate double fault stack");

    let syscall_stack = mm
        .map(DOUBLE_FAULT_STACK_SIZE, MappingFlags::WRITE)
        .expect("failed to allocate double fault stack");

    let ring0_stack = mm
        .map(RING0_STACK_SIZE, MappingFlags::WRITE)
        .expect("failed to allocate ring0 stack");

    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        VirtAddr::new(df_stack.memory().begin().as_u64() + DOUBLE_FAULT_STACK_SIZE as u64);
    tss.interrupt_stack_table[SYSCALL_IST_INDEX as usize] =
        VirtAddr::new(syscall_stack.memory().begin().as_u64() + SYSCALL_IST_INDEX as u64);
    tss.privilege_stack_table[0] =
        VirtAddr::new(ring0_stack.memory().begin().as_u64() + RING0_STACK_SIZE as u64);

    // TODO: maybe store them in static?
    mem::forget(df_stack);
    mem::forget(syscall_stack);
    mem::forget(ring0_stack);

    unsafe {
        TSS.finish_init(tss);
    }
    &TSS
}

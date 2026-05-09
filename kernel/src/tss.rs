use core::mem;

use arch_x86_64::{addr::VirtAddr, block::BlockAddress, frage::L0_PAGE_SIZE, structures::tss::TaskStateSegment};

use crate::{
    common::LateInit,
    memory::{MappingFlags, MemorySegment},
};

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const NM_PANICKING_IST_INDEX: u16 = 1;
pub const DEBUG_IST_INDEX: u16 = 2;

const DOUBLE_FAULT_STACK_SIZE: usize = L0_PAGE_SIZE * 5;
const NM_PANICKING_STACK_SIZE: usize = L0_PAGE_SIZE;
const DEBUG_STACK_SIZE: usize = L0_PAGE_SIZE * 5;
const RING0_STACK_SIZE: usize = L0_PAGE_SIZE * 5;

static TSS: LateInit<TaskStateSegment> = LateInit::new();

pub fn init(mm: &impl MemorySegment) -> &'static TaskStateSegment {
    let df_stack = mm
        .map(DOUBLE_FAULT_STACK_SIZE, MappingFlags::WRITE)
        .expect("failed to allocate double fault stack");

    let nm_panicking_stack = mm
        .map(DOUBLE_FAULT_STACK_SIZE, MappingFlags::WRITE)
        .expect("failed to allocate double fault stack");

    let debug_stack = mm
        .map(DOUBLE_FAULT_STACK_SIZE, MappingFlags::WRITE)
        .expect("failed to allocate double fault stack");

    let ring0_stack = mm
        .map(RING0_STACK_SIZE, MappingFlags::WRITE)
        .expect("failed to allocate ring0 stack");

    let mut tss = TaskStateSegment::new();

    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        VirtAddr::new(df_stack.memory().range().end.as_u64());

    tss.interrupt_stack_table[NM_PANICKING_IST_INDEX as usize] =
        VirtAddr::new(nm_panicking_stack.memory().range().end.as_u64());

    tss.interrupt_stack_table[DEBUG_IST_INDEX as usize] =
        VirtAddr::new(debug_stack.memory().range().end.as_u64());

    tss.privilege_stack_table[0] =
        VirtAddr::new(ring0_stack.memory().range().end.as_u64());

    // TODO: maybe store them in static?
    mem::forget(df_stack);
    mem::forget(nm_panicking_stack);
    mem::forget(debug_stack);
    mem::forget(ring0_stack);

    unsafe {
        TSS.finish_init(tss);
    }
    &TSS
}

pub fn ring0_rsp() -> u64 {
    TSS.privilege_stack_table[0].as_u64()
}

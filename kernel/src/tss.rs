use arch_x86_64::{addr::VirtAddr, pte::PageTableFlags, structures::tss::TaskStateSegment};
use crate::late_init::LateInit;
use crate::memory::MemoryManager;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
const DOUBLE_FAULT_STACK_SIZE: usize = 4096 * 5;
const RING0_STACK_SIZE: usize = 4096 * 5;

static TSS: LateInit<TaskStateSegment> = LateInit::new();

pub fn init(mm: &mut impl MemoryManager) -> &'static TaskStateSegment {
    let df_stack = mm
        .mmap(DOUBLE_FAULT_STACK_SIZE, PageTableFlags::PRESENT | PageTableFlags::WRITABLE)
        .expect("failed to allocate double fault stack");

    let ring0_stack = mm
        .mmap(RING0_STACK_SIZE, PageTableFlags::PRESENT | PageTableFlags::WRITABLE)
        .expect("failed to allocate ring0 stack");

    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        VirtAddr::new(df_stack.start.as_u64() + DOUBLE_FAULT_STACK_SIZE as u64);
    tss.privilege_stack_table[0] =
        VirtAddr::new(ring0_stack.start.as_u64() + RING0_STACK_SIZE as u64);

    unsafe { TSS.finish_init(tss); }
    &TSS
}

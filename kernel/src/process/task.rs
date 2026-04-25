use arch_x86_64::instructions::segmentation::{CS, SS, Segment};
use crate::interrupts::context::InterruptContext;
use crate::memory::MappingHandle;
use super::context::FullContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskId(pub u64);

pub struct Task {
    pub id: TaskId,
    pub context: FullContext,
    pub stack: MappingHandle,
}

impl Task {
    pub fn new(id: TaskId, entry: fn(), stack: MappingHandle) -> Self {
        let stack_top = stack.start.as_u64() + stack.size as u64;
        let context = FullContext {
            general_purpose: Default::default(),
            interrupt_context: InterruptContext {
                error_code: Default::default(),
                rip: entry as u64,
                cs: CS::get_reg().0 as u64,
                rflags: 0x202,
                rsp: stack_top,
                ss: SS::get_reg().0 as u64,
            },
        };
        Self { id, context, stack }
    }
}

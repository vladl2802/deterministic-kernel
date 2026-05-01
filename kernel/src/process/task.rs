use core::fmt;

use super::context::FullContext;
use crate::interrupts::context::InterruptContext;
use crate::memory::MappingHandle;
use arch_x86_64::instructions::segmentation::{CS, SS, Segment};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskState {
    Running,
    Preempteed,
    Stopped,
}

#[derive(Debug, Clone, Copy)]
pub struct Task {
    state: TaskState,
    id: TaskId,
    context: FullContext,
    stack: MappingHandle,
}

#[derive(Debug, Clone, Copy)]
pub struct TaskStateShort<'a>(&'a Task);

impl Task {
    pub fn new(id: TaskId, entry: fn() -> !, stack: MappingHandle) -> Self {
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
        Self {
            state: TaskState::Preempteed,
            id,
            context,
            stack,
        }
    }

    pub fn id(&self) -> TaskId {
        self.id
    }

    pub fn run(&mut self) -> FullContext {
        assert!(
            self.state == TaskState::Preempteed,
            "Attempt to run task ({})",
            self.short_state(),
        );
        self.state = TaskState::Running;
        // TODO: in future it makes sence to separate prepare_run and run
        self.context
    }

    pub fn preempt(&mut self, context: FullContext) {
        assert!(
            self.state == TaskState::Running,
            "Attempt to run task ({})",
            self.short_state(),
        );
        self.state = TaskState::Preempteed;
        self.context = context;
    }

    pub fn stop(&mut self) {
        assert!(
            self.state == TaskState::Preempteed,
            "Attemp to stop task ({})",
            self.short_state()
        );
        self.state = TaskState::Stopped;
    }

    pub fn short_state(&self) -> TaskStateShort<'_> {
        TaskStateShort(self)
    }
}

impl<'a> fmt::Display for TaskStateShort<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"id", &self.0.id)
            .entry(&"state", &self.0.state)
            .finish()
    }
}

use arch_x86_64::pte::PageTableFlags;
use log;
use crate::memory::MemoryManager;
use super::task::{Task, TaskId};

const MAX_TASKS: usize = 16;
pub const TASK_STACK_SIZE: usize = 4096 * 4;

pub struct TaskTable {
    tasks: [Option<Task>; MAX_TASKS],
    next_id: u64,
}

impl TaskTable {
    pub const fn new() -> Self {
        Self { tasks: [const { None }; MAX_TASKS], next_id: 0 }
    }

    pub fn first(&self) -> Option<TaskId> {
        self.tasks.iter().find_map(|t| t.as_ref().map(|t| t.id()))
    }

    pub fn spawn(&mut self, entry: fn() -> !, mm: &mut impl MemoryManager) -> TaskId {
        let id = TaskId(self.next_id);
        self.next_id += 1;
        let stack = mm
            .mmap(TASK_STACK_SIZE, PageTableFlags::PRESENT | PageTableFlags::WRITABLE)
            .expect("failed to allocate task stack");
        log::info!("allocated stack: {:?} {:?}", stack.start, stack.size);
        self.insert(Task::new(id, entry, stack));
        id
    }

    pub fn get_mut(&mut self, id: TaskId) -> Option<&mut Task> {
        self.tasks.iter_mut().find_map(|t| t.as_mut().filter(|t| t.id() == id))
    }

    pub fn next_after(&self, current: Option<TaskId>) -> Option<TaskId> {
        let Some(id) = current else { return self.first(); };
        let start = self.tasks.iter().position(|t| t.as_ref().map_or(false, |t| t.id() == id))?;
        for i in 1..=MAX_TASKS {
            if let Some(task) = &self.tasks[(start + i) % MAX_TASKS] {
                return Some(task.id());
            }
        }
        None
    }

    pub fn remove(&mut self, id: TaskId) {
        for slot in &mut self.tasks {
            if slot.as_ref().map_or(false, |t| t.id() == id) {
                *slot = None;
                return;
            }
        }
    }

    fn insert(&mut self, task: Task) {
        for slot in &mut self.tasks {
            if slot.is_none() {
                *slot = Some(task);
                return;
            }
        }
        panic!("TaskTable is full");
    }
}

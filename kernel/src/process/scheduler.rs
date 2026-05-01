use crate::late_init::LateInit;
use crate::memory::MemoryManager;
use crate::single_thread_lock::SingleThreadLock;

use super::context::{FullContext, InterruptHandler};
use super::table::TaskTable;
use super::task::TaskId;

struct Scheduler {
    current: Option<TaskId>,
}

pub struct SchedulerHandler;

impl InterruptHandler for SchedulerHandler {
    extern "C" fn handle(current: *mut FullContext) -> *mut FullContext {
        let current_id = SCHEDULER.with_lock(|sched| sched.current);
        let next_id = TABLE.with_lock(|table| table.next_after(current_id));

        let next_id = next_id.or(current_id);
        if current_id == next_id {
            return current;
        }

        SCHEDULER.with_lock(|sched| sched.current = next_id);

        if let Some(next_id) = next_id {
            let next_ctx = TABLE.with_lock(|table| {
                if let Some(cur_id) = current_id {
                    table.get_mut(cur_id).unwrap().preempt(unsafe { current.read() });
                }
                table.get_mut(next_id).unwrap().run()
            });
            unsafe { current.write(next_ctx) };
        }

        current
    }
}

static TABLE: LateInit<SingleThreadLock<TaskTable>> = LateInit::new();
static SCHEDULER: LateInit<SingleThreadLock<Scheduler>> = LateInit::new();

pub fn init() {
    unsafe {
        TABLE.finish_init(SingleThreadLock::new_unlocked(TaskTable::new()));
        SCHEDULER.finish_init(SingleThreadLock::new_unlocked(Scheduler { current: None }));
    }
}

pub fn spawn(entry: fn() -> !, mm: &mut impl MemoryManager) -> TaskId {
    TABLE.with_lock(|table| table.spawn(entry, mm))
}

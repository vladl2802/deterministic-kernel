use super::context::{FullContext, InterruptHandler};
use super::table::TaskTable;
use super::task::TaskId;
use crate::late_init::LateInit;
use crate::memory::MemoryManager;
use crate::single_thread_lock::SingleThreadLock;

struct Scheduler {
    current: Option<TaskId>,
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

pub struct SchedulerHandler;

impl InterruptHandler for SchedulerHandler {
    extern "C" fn handle(current: *mut FullContext) -> *mut FullContext {
        let (current_id, next_id) = SCHEDULER.with_lock(|sched| {
            let next = TABLE.with_lock(|table| table.next_after(sched.current));
            let cur = sched.current;
            sched.current = next;
            (cur, next)
        });

        let Some(next_id) = next_id else { return current; };
        if current_id == Some(next_id) {
            return current;
        }

        TABLE.with_lock(|table| {
            if let Some(cur_id) = current_id {
                table.get_mut(cur_id).unwrap().preempt(unsafe { current.read() });
            }
            let next_ctx = table.get_mut(next_id).unwrap().run();
            unsafe { current.write(next_ctx) };
        });

        current
    }
}

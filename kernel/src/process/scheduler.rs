use crate::{
    common::{LateInit, SingleThreadLock},
    memory::MemoryManager,
};

use super::{
    context::{FullContext, InterruptHandler},
    table::TaskTable,
    task::TaskId,
};

struct Scheduler {
    current: Option<TaskId>,
}

pub fn exit_current(current: *mut FullContext) -> *mut FullContext {
    log::info!("exiting current");

    let current_id = SCHEDULER.with_lock(|sched| sched.current);
    let next_id = TABLE.with_lock(|table| table.next_after(current_id));

    if let Some(current_id) = current_id {
        TABLE.with_lock(|table| {
            table.get_mut(current_id).unwrap().stop();
            table.remove(current_id);
        });
    }

    SCHEDULER.with_lock(|sched| sched.current = next_id);
    if let Some(next_id) = next_id {
        TABLE.with_lock(|table| {
            let next_ctx = table.get_mut(next_id).unwrap().run();
            unsafe { current.write(next_ctx) };
        });
    }

    current
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

pub fn spawn(entry: fn() -> !, mm: &impl MemoryManager) -> TaskId {
    TABLE.with_lock(|table| table.spawn(entry, mm))
}

use arch_x86_64::instructions::port;

pub use arch_x86_64::protocol::KernelEvent;

use crate::{late_init::LateInit, single_thread_lock::SingleThreadLock};

struct EventPort(LateInit<SingleThreadLock<port::Port<u8>>>);

unsafe impl Send for EventPort {}
unsafe impl Sync for EventPort {}

pub(crate) fn init(event_port: u16) {
    unsafe { EVENT_PORT.0.finish_init(SingleThreadLock::new_unlocked(port::Port::new(event_port))) };
}

pub fn send(event: KernelEvent) {
    EVENT_PORT
        .0
        .with_lock(|port| unsafe { port.write(event as u8) });
}

static EVENT_PORT: EventPort = EventPort(LateInit::new());

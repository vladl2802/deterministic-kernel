use core::cell::UnsafeCell;

use arch_x86_64::instructions::port;

pub use arch_x86_64::protocol::KernelEvent;

struct EventPort(UnsafeCell<Option<port::Port<u8>>>);

unsafe impl Send for EventPort {}
unsafe impl Sync for EventPort {}

pub(crate) fn init(event_port: u16) {
    unsafe { *EVENT_PORT.0.get() = Some(port::Port::new(event_port)) };
}

pub fn send(event: KernelEvent) {
    let port = unsafe { EVENT_PORT.0.get().as_mut().unwrap() };
    let port = port.as_mut().unwrap();
    unsafe { port.write(event as u8) };
}

static EVENT_PORT: EventPort = EventPort(UnsafeCell::new(None));

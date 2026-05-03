use arch_x86_64::{instructions, protocol::HIT_PORT};

mod late_init;
mod single_thread_lock;
mod static_struct;

pub use late_init::LateInit;
pub use single_thread_lock::SingleThreadLock;
pub(crate) use static_struct::{StaticStructWrapper, declare_static_struct};

pub unsafe fn halt() -> ! {
    loop {
        instructions::hlt()
    }
}

pub fn hit(value: u8) {
    let mut port = instructions::port::Port::new(HIT_PORT);
    unsafe { port.write(value) }
}

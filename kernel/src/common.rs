use arch_x86_64::{instructions, protocol::HIT_PORT};

pub unsafe fn halt() -> ! {
    loop {
        instructions::hlt()
    }
}

pub fn hit(value: u8) {
    let mut port = instructions::port::Port::new(HIT_PORT);
    unsafe { port.write(value) }
}

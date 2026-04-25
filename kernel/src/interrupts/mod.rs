pub mod context;
mod handler;
mod idt;

pub fn init() {
    idt::init();
}

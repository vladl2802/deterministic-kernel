use arch_x86_64::instructions::port::Port;
use log::info;
use super::context::{FullContext, InterruptHandler, interrupt_entry};
use super::scheduler::SchedulerHandler;

const PIC_MASTER_CMD: u16 = 0x20;
const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_CMD: u16 = 0xA0;
const PIC_SLAVE_DATA: u16 = 0xA1;
const PIC_EOI: u8 = 0x20;

const PIT_CHANNEL0: u16 = 0x40;
const PIT_CMD: u16 = 0x43;
const PIT_DIVISOR: u16 = 11932; // ~100 Hz

struct TimerHandler;

impl InterruptHandler for TimerHandler {
    extern "C" fn handle(current: *mut FullContext) -> *mut FullContext {
        info!("handle");
        let next = SchedulerHandler::handle(current);
        unsafe { Port::<u8>::new(PIC_MASTER_CMD).write(PIC_EOI) };
        next
    }
}

pub(crate) const TIMER_INTERRUPT: unsafe extern "C" fn() = interrupt_entry::<TimerHandler>;

pub fn init() {
    unsafe { pic_init() };
    unsafe { pit_init() };
}

unsafe fn pic_init() {
    unsafe {
        Port::<u8>::new(PIC_MASTER_CMD).write(0x11);
        Port::<u8>::new(PIC_SLAVE_CMD).write(0x11);
        Port::<u8>::new(PIC_MASTER_DATA).write(32);
        Port::<u8>::new(PIC_SLAVE_DATA).write(40);
        Port::<u8>::new(PIC_MASTER_DATA).write(4);
        Port::<u8>::new(PIC_SLAVE_DATA).write(2);
        Port::<u8>::new(PIC_MASTER_DATA).write(0x01);
        Port::<u8>::new(PIC_SLAVE_DATA).write(0x01);
        Port::<u8>::new(PIC_MASTER_DATA).write(0xFE);
        Port::<u8>::new(PIC_SLAVE_DATA).write(0xFF);
    }
}

unsafe fn pit_init() {
    unsafe {
        Port::<u8>::new(PIT_CMD).write(0x34);
        Port::<u8>::new(PIT_CHANNEL0).write((PIT_DIVISOR & 0xFF) as u8);
        Port::<u8>::new(PIT_CHANNEL0).write((PIT_DIVISOR >> 8) as u8);
    }
}

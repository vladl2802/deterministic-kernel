use arch_x86_64::{addr::VirtAddr, structures::idt::InterruptDescriptorTable};

use crate::{common::LateInit, tss};

use super::handler;

pub static IDT: LateInit<InterruptDescriptorTable> = LateInit::new();

macro_rules! set_handler {
    ($idt:ident, $name:ident) => {
        $idt.$name.set_handler_fn(handler::$name)
    };
}

pub fn init() {
    let mut idt = InterruptDescriptorTable::new();
    set_handler!(idt, divide_error);
    set_handler!(idt, debug);
    set_handler!(idt, non_maskable_interrupt);
    set_handler!(idt, breakpoint);
    set_handler!(idt, overflow);
    set_handler!(idt, bound_range_exceeded);
    set_handler!(idt, invalid_opcode);
    set_handler!(idt, device_not_available);
    unsafe { set_handler!(idt, double_fault).set_stack_index(tss::DOUBLE_FAULT_IST_INDEX) };
    set_handler!(idt, invalid_tss);
    set_handler!(idt, segment_not_present);
    set_handler!(idt, stack_segment_fault);
    set_handler!(idt, general_protection_fault);
    set_handler!(idt, page_fault);
    set_handler!(idt, x87_floating_point);
    set_handler!(idt, alignment_check);
    set_handler!(idt, machine_check);
    set_handler!(idt, simd_floating_point);
    set_handler!(idt, virtualization);
    set_handler!(idt, cp_protection_exception);
    set_handler!(idt, hv_injection_exception);
    set_handler!(idt, vmm_communication_exception);
    set_handler!(idt, security_exception);
    unsafe {
        idt[32].set_handler_addr(VirtAddr::new(handler::timer_interrupt as u64));
        idt[0x80]
            .set_handler_addr(VirtAddr::new(handler::syscall_interrupt as u64))
            .set_stack_index(tss::SYSCALL_IST_INDEX);
        IDT.finish_init(idt);
    }
    IDT.load();
}

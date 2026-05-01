use arch_x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};
use log::trace;

pub(super) use crate::process::syscall::SYSCALL_INTERRUPT as syscall_interrupt;
pub(super) use crate::process::timer::TIMER_INTERRUPT as timer_interrupt;

macro_rules! make_handler {
    (panic, $name:ident) => {
        pub extern "x86-interrupt" fn $name(frame: InterruptStackFrame) {
            panic!(concat!(stringify!($name), "\n{:#?}"), frame);
        }
    };
    (trace, $name:ident) => {
        pub extern "x86-interrupt" fn $name(frame: InterruptStackFrame) {
            trace!(concat!(stringify!($name), "\n{:#?}"), frame);
        }
    };
    (panic_err, $name:ident) => {
        pub extern "x86-interrupt" fn $name(frame: InterruptStackFrame, error_code: u64) {
            panic!(concat!(stringify!($name), " err={:#x}\n{:#?}"), error_code, frame);
        }
    };
    (trace_err, $name:ident) => {
        pub extern "x86-interrupt" fn $name(frame: InterruptStackFrame, error_code: u64) {
            trace!(concat!(stringify!($name), " err={:#x}\n{:#?}"), error_code, frame);
        }
    };
}

make_handler!(panic, divide_error);
make_handler!(trace, debug);
make_handler!(trace, non_maskable_interrupt);
make_handler!(trace, breakpoint);
make_handler!(panic, overflow);
make_handler!(panic, bound_range_exceeded);
make_handler!(panic, invalid_opcode);
make_handler!(panic, device_not_available);
make_handler!(panic_err, invalid_tss);
make_handler!(panic_err, segment_not_present);
make_handler!(panic_err, stack_segment_fault);
make_handler!(panic_err, general_protection_fault);
make_handler!(panic, x87_floating_point);
make_handler!(panic_err, alignment_check);
make_handler!(panic, simd_floating_point);
make_handler!(trace, virtualization);
make_handler!(panic_err, cp_protection_exception);
make_handler!(trace, hv_injection_exception);
make_handler!(trace_err, vmm_communication_exception);
make_handler!(panic_err, security_exception);

pub extern "x86-interrupt" fn page_fault(frame: InterruptStackFrame, error_code: PageFaultErrorCode) {
    panic!("page_fault err={error_code:#?}\n{frame:#?}");
}

pub extern "x86-interrupt" fn double_fault(frame: InterruptStackFrame, error_code: u64) -> ! {
    panic!("double_fault\n{frame:#?}\n{error_code:#?}");
}

pub extern "x86-interrupt" fn machine_check(frame: InterruptStackFrame) -> ! {
    panic!("machine_check\n{frame:#?}");
}

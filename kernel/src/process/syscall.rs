use super::context::{FullContext, InterruptHandler, interrupt_entry};
use super::scheduler;

#[repr(u64)]
pub enum SyscallNumber {
    Exit = 0,
}

impl SyscallNumber {
    pub fn try_from_register(register: u64) -> Option<Self> {
        match register {
            0 => Some(SyscallNumber::Exit),
            _ => None,
        }
    }
}

pub fn exit() -> ! {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("rax") SyscallNumber::Exit as u64,
            options(noreturn)
        );
    }
}

struct SyscallHandler;

impl InterruptHandler for SyscallHandler {
    extern "C" fn handle(current: *mut FullContext) -> *mut FullContext {

        let rax = unsafe { (*current).general_purpose[0] };
        match SyscallNumber::try_from_register(rax).unwrap() {
            SyscallNumber::Exit => scheduler::exit_current(current),
        }
    }
}

pub(crate) const SYSCALL_INTERRUPT: unsafe extern "C" fn() = interrupt_entry::<SyscallHandler>;

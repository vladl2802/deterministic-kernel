use core::{mem, ptr};

use crate::tss;

use super::{context::FullContext, scheduler};

// x86_64 crate does not export those
// x86 crate does export those, but it looks unmaintained
// Maybe use x86 here
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

#[repr(C)]
struct SyscallUserStorage {
    user_rsp: u64,
    saved_rax: u64,
    kernel_rsp: u64,
}

static mut SYSCALL_STORAGE: SyscallUserStorage = SyscallUserStorage { user_rsp: 0, saved_rax: 0, kernel_rsp: 0 };

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
            "syscall",
            in("rax") SyscallNumber::Exit as u64,
            options(noreturn)
        );
    }
}

extern "C" fn syscall_handler(current: *mut FullContext) -> *mut FullContext {
    let rax = unsafe { (*current).general_purpose[0] };
    match SyscallNumber::try_from_register(rax).unwrap() {
        SyscallNumber::Exit => scheduler::exit_current(current),
    }
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        "swapgs",
        "mov gs:[{user_rsp}], rsp",
        // We need rax to access segment registers, save it
        "mov gs:[{saved_rax}], rax",
        // Switch to kernel stack
        // This is needed only to support calling syscalls from the kernel code
        // because ring0 switch stack will handle this for the user
        // Maybe drop it at some point.
        "mov rsp, gs:[{kernel_rsp}]",

        // Build iretq frame: SS, RSP, RFLAGS, CS, RIP
        "xor rax, rax",
        "mov ax, ss",
        "push rax",
        // rsp saved in the temporal storaged
        "mov rax, gs:[{user_rsp}]",
        "push rax",
        // RFLAGS saved by syscall
        "push r11",
        "xor rax, rax",
        "mov ax, cs",
        "push rax",
        // return RIP saved by syscall
        "push rcx",

        // GP registers
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rbp",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rbx",
        // Restore rax
        "mov rax, gs:[{saved_rax}]",
        "push rax",

        "mov rdi, rsp",
        "call {handler}",
        "mov rsp, rax",

        "pop rax",
        "pop rbx",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "pop rbp",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",

        "swapgs",
        "iretq",
        user_rsp = const mem::offset_of!(SyscallUserStorage, user_rsp),
        saved_rax = const mem::offset_of!(SyscallUserStorage, saved_rax),
        kernel_rsp = const mem::offset_of!(SyscallUserStorage, kernel_rsp),
        handler = sym syscall_handler,
    )
}

pub fn init() {
    use arch_x86_64::instructions::segmentation::{CS, Segment};
    use arch_x86_64::registers::model_specific::Msr;

    let kernel_cs = CS::get_reg().0 as u64;
    let star = kernel_cs << 32;

    unsafe {
        SYSCALL_STORAGE.kernel_rsp = tss::ring0_rsp();
        let scratch_addr = ptr::addr_of!(SYSCALL_STORAGE) as u64;
        Msr::new(MSR_STAR).write(star);
        Msr::new(MSR_LSTAR).write(syscall_entry as *const () as u64);
        // Turn off IF because interrupts are extremly dangereous around swapgs
        Msr::new(MSR_SFMASK).write(1 << 9);
        Msr::new(MSR_KERNEL_GS_BASE).write(scratch_addr);
    }
}

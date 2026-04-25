use crate::interrupts::context::InterruptContext;

// rax-rdx = 4, (rsi, sdi, rbp) = 3, r8-r15 = 8
pub const GP_REGISTERS_COUNT: usize = 15;

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub(super) struct FullContext {
    pub general_purpose: [u64; GP_REGISTERS_COUNT],
    // TODO: avx registers
    pub interrupt_context: InterruptContext,
}

pub (super) trait InterruptHandler {
    extern "C" fn handle(current: *mut FullContext) -> *mut FullContext;
}

#[unsafe(naked)]
pub(super) unsafe extern "C" fn interrupt_entry<H: InterruptHandler>() {
    core::arch::naked_asm!(
        // Interrupt context is saved by the cpu
        // Save all general-purpose registers
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
        "push rax",

        // FullContext structure has been built on the stack, rsp is the valid pointer to it
        "mov rdi, rsp",

        "call {handler}",

        // Handler returned pointer to the new context
        "mov rsp, rax",

        // Restore all general-purpose registers
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

        // Only interrupt context has remained on the stack, iretq will use it
        "iretq",

        handler = sym H::handle,
    )
}

#![feature(maybe_uninit_fill)]
#![feature(unsafe_cell_access)]

use core::slice;
use std::{
    cell::{Cell, UnsafeCell},
    cmp, env,
    fs::File,
    io::Read,
    mem::{self, MaybeUninit},
    ops::Range,
    ptr::null_mut,
};

use kvm_bindings::{KVM_MEM_LOG_DIRTY_PAGES, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};

use arch_x86_64::{
    addr::{PhysAddr, VirtAddr},
    frage::{self, L0_PAGE_SIZE, L0Page, L1HugePage},
    protocol, pte,
};
use common::{align_marker::AlignMarker, try_alignment};
use goblin::elf::{Elf, program_header};
use nix::libc;
use tracing::{Level, span, trace, warn};
use tracing_subscriber;

// TODO: unwrap -> anyhow or something similar

const MEM_SIZE: u64 = 6 * 1024 * 1024;
const LOG_PORT: u16 = 0xE9;
const EVENT_PORT: u16 = 0xEA;

struct Frame<'a, const SIZE: usize>
where
    frage::PageAligment: AlignMarker<SIZE>,
{
    phys: PhysAddr,
    page: &'a mut frage::Page<SIZE>,
}

impl<'a, const SIZE: usize> Frame<'a, SIZE>
where
    frage::PageAligment: AlignMarker<SIZE>,
{
    fn new(phys: PhysAddr, page: &'a mut frage::Page<SIZE>) -> Self {
        assert!(phys.is_aligned(frage::Page::SIZE));
        Self { phys, page }
    }
}

type L0Frame<'a> = Frame<'a, L0_PAGE_SIZE>;

struct AllocatingPageTable<'a> {
    level: u8,
    allocated: u16,
    virt_space_base: VirtAddr,
    pte: &'a mut pte::PageTable,
}

impl<'a> AllocatingPageTable<'a> {
    fn root(frame: Frame<'a, L0_PAGE_SIZE>) -> Self {
        AllocatingPageTable {
            level: 4,
            allocated: 0,
            virt_space_base: VirtAddr::zero(),
            pte: pte::PageTable::new_non_present(frame.page),
        }
    }

    fn child_virt_addr_base(&self, index: u16) -> VirtAddr {
        let size = L0Page::SIZE << ((self.level - 1) as usize * pte::PAGE_TABLE_INDEX_BITS);
        VirtAddr::new_truncate(self.virt_space_base.as_u64() + size * index as u64)
    }

    fn allocate(&mut self, phys: PhysAddr, flags: pte::PageTableFlags) -> Option<VirtAddr> {
        let span = span!(Level::TRACE, "AllocPTE.allocate");
        let _enter = span.enter();
        let index = self.allocated as usize;
        let res = if index < pte::PAGE_TABLE_ENTRY_COUNT {
            self.pte[index] = pte::PageTableEntry::new(phys, flags);
            self.allocated += 1;
            let virt = self.child_virt_addr_base(self.allocated - 1);
            Some(virt)
        } else {
            None
        };
        trace!(phys = ?phys, flags = %flags, base = ?res);
        res
    }

    fn allocate_pte(
        &mut self,
        frame: Frame<'a, L0_PAGE_SIZE>,
        flags: pte::PageTableFlags,
    ) -> Option<Self> {
        let virt_space_base = self.allocate(frame.phys, flags)?;
        Some(AllocatingPageTable {
            level: self.level - 1,
            allocated: 0,
            virt_space_base,
            pte: pte::PageTable::new_non_present(frame.page),
        })
    }
}

trait FrameAllocator<const SIZE: usize>
where
    frage::PageAligment: AlignMarker<SIZE>,
{
    fn alloc_frame(&self) -> Option<Frame<'_, SIZE>>;
}

struct BumpFrameAllocator<'a> {
    memory: UnsafeCell<&'a mut [L0Page]>,
    phys_offset: Cell<PhysAddr>,
}

impl<'a> BumpFrameAllocator<'a> {
    fn new(memory: &'a mut [MaybeUninit<u8>], phys_offset: PhysAddr) -> Option<Self> {
        assert!(phys_offset.is_aligned(L0Page::SIZE));
        let memory = try_alignment!(unsafe { memory.align_to_mut::<L0Page>() })?;
        Some(Self {
            memory: UnsafeCell::new(memory),
            phys_offset: Cell::new(phys_offset),
        })
    }

    fn memory(&self) -> &'a mut [L0Page] {
        unsafe { *self.memory.get() }
    }
}

impl<'a> FrameAllocator<L0_PAGE_SIZE> for BumpFrameAllocator<'a> {
    fn alloc_frame(&self) -> Option<L0Frame<'_>> {
        let (first, rest) = self.memory().split_first_mut()?;
        unsafe { self.memory.replace(rest) };
        Some(L0Frame::new(
            self.phys_offset
                .replace(self.phys_offset.get() + L0Page::SIZE),
            first,
        ))
    }
}

struct KernelBinary<'a> {
    binary: &'a [u8],
    elf: Elf<'a>,
}

impl<'a> KernelBinary<'a> {
    fn from_binary(binary: &'a [u8]) -> Self {
        Self {
            binary,
            elf: Elf::parse(binary).unwrap(),
        }
    }

    fn needed_memory(&self) -> Option<Range<PhysAddr>> {
        let needed_range = self
            .elf
            .program_headers
            .iter()
            .map(|header| Range {
                start: header.p_vaddr,
                end: header.p_vaddr + header.p_memsz,
            })
            .fold(None, |pref: Option<Range<u64>>, range| {
                Some(match pref {
                    Some(pref) => Range {
                        start: cmp::min(pref.start, range.start),
                        end: cmp::max(pref.end, range.end),
                    },
                    None => range,
                })
            });
        needed_range.map(|Range { start, end }| {
            let start = PhysAddr::new(start).align_down(L0Page::SIZE);
            let end = PhysAddr::new(end).align_up(L0Page::SIZE);
            Range { start, end }
        })
    }

    fn load(&self, mem: &'a mut [MaybeUninit<u8>]) {
        for header in &self.elf.program_headers {
            if header.p_type != program_header::PT_LOAD {
                continue;
            }

            let file_offset = header.p_offset as usize;
            let file_size = header.p_filesz as usize;
            let mem_size = header.p_memsz as usize;
            let dst = header.p_vaddr as usize;

            // TODO: add checks that mem is big enough

            mem[dst..dst + file_size]
                .write_copy_of_slice(&self.binary[file_offset..file_offset + file_size]);
            if mem_size > file_size {
                mem[dst + file_size..dst + mem_size].write_filled(0);
            }
        }
    }

    fn entry(&self) -> u64 {
        self.elf.entry
    }
}

fn setup_physical_memory(vm: &VmFd) -> &mut [MaybeUninit<u8>] {
    let memory_ptr = unsafe {
        libc::mmap(
            null_mut(),
            MEM_SIZE as usize,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        ) as *mut u8
    };
    // TODO: get_log_dirty returns per-slot bitmaps. So there is point in sepparating
    // kernel and user memory.
    let memory_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: MEM_SIZE,
        userspace_addr: memory_ptr as u64,
        flags: KVM_MEM_LOG_DIRTY_PAGES,
    };
    unsafe { vm.set_user_memory_region(memory_region).unwrap() };
    unsafe { slice::from_raw_parts_mut(memory_ptr as *mut MaybeUninit<_>, MEM_SIZE as usize) }
}

#[derive(Debug, Clone, Copy)]
struct AddressSpaceState {
    pt4: PhysAddr,
    entry: VirtAddr,
    stack_top: VirtAddr,
    boot_info: VirtAddr,
}

impl AddressSpaceState {
    fn kernel_flags() -> pte::PageTableFlags {
        use pte::PageTableFlags as fs;
        fs::PRESENT | fs::WRITABLE | fs::EXECUTABLE
    }

    fn stack_flags() -> pte::PageTableFlags {
        use pte::PageTableFlags as fs;
        fs::PRESENT | fs::WRITABLE
    }

    fn boot_info_flags() -> pte::PageTableFlags {
        use pte::PageTableFlags as fs;
        fs::PRESENT
    }

    fn general_flags() -> pte::PageTableFlags {
        Self::kernel_flags() | Self::stack_flags() | Self::boot_info_flags()
    }

    fn setup(memory: &mut [MaybeUninit<u8>], kernel: &KernelBinary) -> Self {
        let span = span!(Level::TRACE, "AddressSpaceState.setup");
        let _enter = span.enter();
        let mut kernel_binary_range = kernel.needed_memory().unwrap();
        kernel_binary_range.end = kernel_binary_range.end.align_up(L1HugePage::SIZE);
        assert!(
            kernel_binary_range.end.as_u64() < MEM_SIZE,
            "Preallocated not enough memory"
        );
        let (kernel_binary_memory, memory) =
            memory.split_at_mut(kernel_binary_range.end.as_u64() as usize);

        let frame_alloc = BumpFrameAllocator::new(memory, kernel_binary_range.end).unwrap();

        let pt4_frame = frame_alloc.alloc_frame().unwrap();
        let pt4_address = pt4_frame.phys;
        let mut pt4 = AllocatingPageTable::root(pt4_frame);

        let pt3_frame = frame_alloc.alloc_frame().unwrap();
        let mut pt3 = pt4.allocate_pte(pt3_frame, Self::general_flags()).unwrap();

        let pt2_frame = frame_alloc.alloc_frame().unwrap();
        let mut pt2 = pt3.allocate_pte(pt2_frame, Self::general_flags()).unwrap();

        let entry = Self::setup_kernel(kernel_binary_memory, &mut pt2, kernel);

        let pt1_frame = frame_alloc.alloc_frame().unwrap();
        let mut pt1 = pt2
            .allocate_pte(pt1_frame, Self::stack_flags() | Self::boot_info_flags())
            .unwrap();

        let stack = Self::setup_stack(&mut pt1, &frame_alloc);
        let boot_info = Self::setup_boot_info(&mut pt1, &frame_alloc);

        Self {
            pt4: pt4_address,
            entry,
            stack_top: stack.end,
            boot_info,
        }
    }

    fn setup_kernel(
        memory: &mut [MaybeUninit<u8>],
        pt2: &mut AllocatingPageTable,
        kernel: &KernelBinary,
    ) -> VirtAddr {
        let span = span!(Level::TRACE, "AddressSpaceState.setup_kernel");
        let _enter = span.enter();
        let end = kernel.needed_memory().unwrap().end;
        let end = end.align_up(L1HugePage::SIZE);
        for addr in (0..end.as_u64()).step_by(L1HugePage::SIZE as usize) {
            pt2.allocate(
                PhysAddr::new(addr),
                Self::kernel_flags() | pte::PageTableFlags::HUGE,
            )
            .unwrap();
        }
        kernel.load(memory);

        VirtAddr::new(kernel.entry())
    }

    fn setup_stack(
        pt1: &mut AllocatingPageTable,
        frame_alloc: &dyn FrameAllocator<L0_PAGE_SIZE>,
    ) -> Range<VirtAddr> {
        let span = span!(Level::TRACE, "AddressSpaceState.setup_stack");
        let _enter = span.enter();
        let pages = 4u64;
        let mut base = None;
        for _ in 0..pages {
            let frame = frame_alloc.alloc_frame().unwrap();
            let virt = pt1.allocate(frame.phys, Self::stack_flags()).unwrap();
            if base.is_none() {
                base = Some(virt);
            }
        }
        let range = Range {
            start: base.unwrap(),
            end: base.unwrap() + L0Page::SIZE * pages,
        };
        trace!(stack_base = ?base, stack = ?range);
        range
    }

    fn setup_boot_info(
        pt1: &mut AllocatingPageTable,
        frame_alloc: &dyn FrameAllocator<L0_PAGE_SIZE>,
    ) -> VirtAddr {
        let span = span!(Level::TRACE, "AddressSpaceState.setup_bootinfo");
        let _enter = span.enter();
        let frame = frame_alloc.alloc_frame().unwrap();
        let virt = pt1.allocate(frame.phys, Self::boot_info_flags()).unwrap();

        let boot_info = protocol::BootInfo {
            logging_port: LOG_PORT,
            event_port: EVENT_PORT,
            memory_regions: &[],
            salt: 0xDEADBEEF,
        };
        let bytes = frame.page.bytes_mut();
        unsafe { (bytes.as_ptr() as *mut protocol::BootInfo).write(boot_info) };

        virt
    }
}

fn setup_sregs(vcpu: &VcpuFd, pt4: PhysAddr) {
    let span = span!(Level::TRACE, "AddressSpaceState.setup_sregs");
    let _enter = span.enter();
    let mut sregs = vcpu.get_sregs().unwrap();

    let code_seg = kvm_bindings::kvm_segment {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: 1 << 3,
        type_: 0b1011, // RX, accessed
        present: 1,
        dpl: 0,
        db: 0,
        s: 1,
        l: 1,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: Default::default(),
    };
    let data_seg = kvm_bindings::kvm_segment {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: 2 << 3,
        type_: 0b0011, // RW, accessed
        present: 1,
        dpl: 0,
        db: 0,
        s: 1,
        l: 0,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: Default::default(),
    };

    sregs.gdt = kvm_bindings::kvm_dtable {
        base: 0,
        limit: 0,
        padding: Default::default(),
    };
    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;

    // Enable long mode
    sregs.cr3 = pt4.as_u64();
    sregs.cr4 |= 1 << 5; // PAE
    sregs.cr0 |= 1 << 0; // PE
    sregs.cr0 |= 1 << 31; // PG
    sregs.efer |= (1 << 8) | (1 << 10) | (1 << 11); // LME|LMA|NXE

    vcpu.set_sregs(&sregs).unwrap();
}

fn setup_vm(kvm: &Kvm, kernel_binary: &str) -> (VmFd, VcpuFd) {
    let span = span!(Level::TRACE, "AddressSpaceState.setup_vm");
    let _enter = span.enter();
    let vm = kvm.create_vm().unwrap();
    // maybe not needed actually?
    // https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt says that
    // > This is needed on Intel hardware
    // > because of a quirk in the virtualization implementation
    vm.set_tss_address(0xfffbd000).unwrap();
    vm.set_identity_map_address(0xffffc000).unwrap();

    let memory = setup_physical_memory(&vm);

    let mut kernel_elf = File::open(kernel_binary).unwrap();
    let mut elf_data = Vec::new();
    kernel_elf.read_to_end(&mut elf_data).unwrap();
    let kernel = KernelBinary::from_binary(&elf_data);

    let address_space = AddressSpaceState::setup(memory, &kernel);

    let vcpu = vm.create_vcpu(0).unwrap();
    let mut cpuid = kvm
        .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .unwrap();
    vcpu.set_cpuid2(&mut cpuid).unwrap();

    setup_sregs(&vcpu, address_space.pt4);

    let mut regs = vcpu.get_regs().unwrap();
    regs.rip = address_space.entry.as_u64();
    regs.rdi = address_space.boot_info.as_u64();
    regs.rsp = address_space.stack_top.as_u64();
    regs.rflags = 0x2;
    vcpu.set_regs(&regs).unwrap();

    (vm, vcpu)
}

struct KernelLogCollector {
    buf: Vec<u8>,
}

impl KernelLogCollector {
    fn new() -> Self {
        KernelLogCollector { buf: Vec::new() }
    }

    fn add_bytes(&mut self, data: &[u8]) {
        data.into_iter().for_each(|byte| self.add_byte(*byte));
    }

    fn add_byte(&mut self, byte: u8) {
        if byte == b'\n' {
            self.flush();
        } else {
            self.buf.push(byte);
        }
    }

    fn flush(&mut self) {
        let buf = mem::replace(&mut self.buf, Vec::new());
        match String::from_utf8(buf) {
            Ok(log) => println!(" > {log}"),
            Err(err) => println!("logging error: {err}"),
        }
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .init();

    let path_to_kernel_binary = env::args().nth(1).unwrap();

    let kvm = Kvm::new().unwrap();

    let (vm, mut vcpu_fd) = setup_vm(&kvm, &path_to_kernel_binary);

    let mut collector = KernelLogCollector::new();

    loop {
        let exit_reason = vcpu_fd.run().expect("run failed");
        // trace!(exit_reason = ?exit_reason);
        match exit_reason {
            VcpuExit::IoIn(addr, data) => {
                println!(
                    "Received an I/O in exit. Address: {:#x}. Data: {:#x}",
                    addr, data[0],
                );
            }
            VcpuExit::IoOut(addr, data) => match addr {
                LOG_PORT => collector.add_bytes(data),
                EVENT_PORT => {
                    let formatted_ev = match protocol::KernelEvent::from_byte(data[0]) {
                        Some(val) => format!("{val}"),
                        None => "Unknown".to_owned(),
                    };
                    warn!("Kernel event {:#x} ({})", data[0], formatted_ev);
                }
                protocol::HIT_PORT => trace!(hit = data[0]),
                _ => trace!(
                    "Recieved port out exit: address={:#x}, data={}",
                    addr,
                    if data.len() == 1 {
                        format!("{:#x}", data[0])
                    } else {
                        format!("{:#x?}", data)
                    },
                ),
            },
            VcpuExit::MmioRead(addr, _data) => {
                println!("Received an MMIO Read Request for the address {:#x}.", addr);
            }
            VcpuExit::MmioWrite(addr, _data) => {
                println!("Received an MMIO Write Request to the address {:#x}.", addr);
                let dirty_pages_bitmap = vm.get_dirty_log(0, MEM_SIZE as usize).unwrap();
                let dirty_pages = dirty_pages_bitmap
                    .into_iter()
                    .map(|page| page.count_ones())
                    .fold(0, |dirty_page_count, i| dirty_page_count + i);
                assert_eq!(dirty_pages, 1);
            }
            VcpuExit::Hlt => break,
            VcpuExit::InternalError => {
                // kvm-ioctl crate hides internal error details
                // afaik because it is not a stable api
                // for the sake of error message I will get those fields by myself
                let kvm_run = vcpu_fd.get_kvm_run();
                let internal = unsafe { kvm_run.__bindgen_anon_1.internal };
                panic!(
                    "InternalError exit reason: suberror={}, ndata={}, data={:?}",
                    internal.suberror, internal.ndata, internal.data
                );
            }
            r => panic!("Unexpected exit reason: {:?}", r),
        }
    }
}

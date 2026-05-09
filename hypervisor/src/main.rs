#![feature(maybe_uninit_fill)]
#![feature(unsafe_cell_access)]

mod guest_phys;
mod loader;

use core::slice;
use std::{
    cell::{Cell, UnsafeCell},
    env,
    fs::File,
    io::Read,
    mem::{self, MaybeUninit},
    ops::Range,
    ptr::null_mut,
};

use kvm_bindings::{
    KVM_MEM_LOG_DIRTY_PAGES, KVM_PIT_SPEAKER_DUMMY, kvm_pit_config, kvm_userspace_memory_region,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use nix::libc;
use tracing::{Level, error, span, trace, warn};
use tracing_subscriber;

use arch_x86_64::{
    addr::{PhysAddr, VirtAddr},
    block::{
        AlignedChunkable, Alignment, BackedBlock, BlockAddress, BlockChunks, DynamicSize, FixedSize,
    },
    frage::{self, L0_PAGE_SIZE, L0Page, L1_HUGE_PAGE_SIZE, L1HugePage},
    protocol, pte,
};
use common::{align_marker::AlignMarker, try_alignment};

use crate::guest_phys::GuestPhysBlock;

// TODO: unwrap -> anyhow or something similar

const LOG_PORT: u16 = 0xE9;
const EVENT_PORT: u16 = 0xEA;

struct Mmap {
    ptr: *mut u8,
    size: usize,
}

impl Mmap {
    fn alloc(size: usize) -> Self {
        let ptr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        } as *mut u8;

        if ptr == libc::MAP_FAILED.cast() {
            panic!("mmap failed: {}", std::io::Error::last_os_error());
        }

        Self { ptr, size }
    }

    fn as_uninit_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        unsafe { slice::from_raw_parts_mut(self.ptr as *mut MaybeUninit<u8>, self.size) }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.size) };
    }
}

struct PhysicalRegion {
    base_phys: PhysAddr,
    memory: Mmap,
}

impl PhysicalRegion {
    pub fn new(memory: Mmap, base_phys: PhysAddr) -> Self {
        assert_eq!(memory.size % L1_HUGE_PAGE_SIZE, 0);
        Self { memory, base_phys }
    }

    fn into_guest_phys(&mut self) -> GuestPhysBlock<'_, DynamicSize, Alignment<L1_HUGE_PAGE_SIZE>> {
        GuestPhysBlock::from_slice(self.base_phys, self.memory.as_uninit_slice())
    }

    fn phys_range(&self) -> Range<PhysAddr> {
        self.base_phys..self.base_phys + self.memory.size as u64
    }
}

pub(crate) struct PhysicalMemory {
    pub static_region: PhysicalRegion,
    pub kernel_dynamic_region: PhysicalRegion,
    pub user_region: PhysicalRegion,
}

impl PhysicalMemory {
    pub const STATIC_REGION_SIZE: usize = 6 * 1024 * 1024;
    pub const KERNEL_DYNAMIC_REGION_SIZE: usize = 16 * 1024 * 1024;
    pub const USER_REGION_SIZE: usize = 16 * 1024 * 1024;

    pub fn setup(vm: &VmFd) -> Self {
        let mut base_phys = PhysAddr::new(0);
        let mut slot = 0;
        let mut allocate = |size: usize| {
            let region = Self::setup_region(vm, slot, base_phys, size);
            slot += 1;
            base_phys += size as u64;
            region
        };

        let static_region = allocate(Self::STATIC_REGION_SIZE);
        let kernel_dynamic_region = allocate(Self::KERNEL_DYNAMIC_REGION_SIZE);
        let user_region = allocate(Self::USER_REGION_SIZE);

        Self {
            static_region,
            kernel_dynamic_region,
            user_region,
        }
    }

    fn setup_region(vm: &VmFd, slot: u32, base_phys: PhysAddr, size: usize) -> PhysicalRegion {
        let memory = Mmap::alloc(size);
        let region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: base_phys.as_u64(),
            memory_size: size as u64,
            userspace_addr: memory.ptr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        unsafe { vm.set_user_memory_region(region).unwrap() };
        PhysicalRegion::new(memory, base_phys)
    }

    pub fn total_phys_size() -> u64 {
        (Self::STATIC_REGION_SIZE + Self::KERNEL_DYNAMIC_REGION_SIZE + Self::USER_REGION_SIZE)
            as u64
    }
}

type L0GuestFrame<'a> = GuestPhysBlock<'a, FixedSize<L0_PAGE_SIZE>, Alignment<L0_PAGE_SIZE>>;

struct AllocatingPageTable<'a> {
    level: u8,
    allocated: u16,
    virt_space_base: VirtAddr,
    entries: &'a mut [pte::PageTableEntry],
}

impl<'a> AllocatingPageTable<'a> {
    fn root(frame: L0GuestFrame<'a>) -> Self {
        AllocatingPageTable {
            level: 4,
            allocated: 0,
            virt_space_base: VirtAddr::zero(),
            entries: pte::PageTable::new_non_present(frame.into_page_mut()).entries_mut(),
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
        let res = if index < self.entries.len() {
            self.entries[index] = pte::PageTableEntry::new(phys, flags);
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
        frame: L0GuestFrame<'a>,
        flags: pte::PageTableFlags,
    ) -> Option<Self> {
        let virt_space_base = self.allocate(frame.begin(), flags)?;
        Some(AllocatingPageTable {
            level: self.level - 1,
            allocated: 0,
            virt_space_base,
            entries: pte::PageTable::new_non_present(frame.into_page_mut()).entries_mut(),
        })
    }

    fn virt_range(&self) -> Range<VirtAddr> {
        self.virt_space_base..self.child_virt_addr_base(self.allocated)
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        let right_base = self.child_virt_addr_base(index as u16);
        let (left, right) = self.entries.split_at_mut(index);
        (
            AllocatingPageTable {
                level: self.level,
                allocated: 0,
                virt_space_base: self.virt_space_base,
                entries: left,
            },
            AllocatingPageTable {
                level: self.level,
                allocated: 0,
                virt_space_base: right_base,
                entries: right,
            },
        )
    }
}

trait FrameAllocator<'a, const SIZE: usize>
where
    frage::PageAligment: AlignMarker<SIZE>,
{
    fn alloc_frame(&self) -> Option<GuestPhysBlock<'a, FixedSize<SIZE>, Alignment<SIZE>>>;
}

struct BumpFrameAllocator<'a> {
    memory: UnsafeCell<&'a mut [L0Page]>,
    phys_offset: Cell<PhysAddr>,
    count: Cell<u64>,
}

impl<'a> BumpFrameAllocator<'a> {
    fn new(
        mut block: GuestPhysBlock<DynamicSize, Alignment<L1_HUGE_PAGE_SIZE>>,
    ) -> Option<Self> {
        let memory = unsafe { &mut *block.as_uninit_ptr_mut() };
        let memory = try_alignment!(unsafe { memory.align_to_mut::<L0Page>() })?;
        Some(BumpFrameAllocator {
            memory: UnsafeCell::new(memory),
            phys_offset: Cell::new(block.begin()),
            count: Cell::new(0),
        })
    }

    fn memory(&self) -> &'a mut [L0Page] {
        unsafe { *self.memory.get() }
    }

    fn frames_allocated(&self) -> u64 {
        self.count.get()
    }
}

impl<'a> FrameAllocator<'a, L0_PAGE_SIZE> for BumpFrameAllocator<'a> {
    fn alloc_frame(&self) -> Option<L0GuestFrame<'a>> {
        let (first, rest) = self.memory().split_first_mut()?;
        unsafe { self.memory.replace(rest) };
        let frame = L0GuestFrame::from_array(
            self.phys_offset
                .replace(self.phys_offset.get() + L0Page::SIZE),
            first.bytes_mut(),
        );
        self.count.set(self.count.get() + 1);
        Some(frame)
    }
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

    fn phys_mapping_flags() -> pte::PageTableFlags {
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

    fn setup(phys_mem: &mut PhysicalMemory, kernel: &loader::KernelBinary) -> Self {
        let span = span!(Level::TRACE, "AddressSpaceState.setup");
        let _enter = span.enter();

        let mut kernel_binary_range = kernel.needed_memory().unwrap();
        kernel_binary_range.end = kernel_binary_range.end.align_up(L1HugePage::SIZE);
        assert!(
            kernel_binary_range.end.as_u64() < PhysicalMemory::STATIC_REGION_SIZE as u64,
            "Preallocated not enough static memory for kernel binary"
        );
        let kernel_n_huge_pages =
            (kernel_binary_range.end.as_u64() / L1_HUGE_PAGE_SIZE as u64) as usize;

        // Frame allocator for page tables — pulls from kernel_dynamic_region
        let tmp = &mut phys_mem.kernel_dynamic_region;
        let kernel_dynamic_memory = tmp.into_guest_phys();
        let frame_alloc = BumpFrameAllocator::new(kernel_dynamic_memory).unwrap();

        // PML4
        let pt4_frame = frame_alloc.alloc_frame().unwrap();
        let pt4_address = pt4_frame.begin();
        let pt4 = AllocatingPageTable::root(pt4_frame);

        // PML4[0..255] = user space low half
        // PML4[256..511] = kernel high half
        let (_, pt4_high) = pt4.split_at(256);

        // Isolate PML4[256]
        let (mut pt4_at_256, pt4_rest) = pt4_high.split_at(1);
        // Isolate PML4[384]
        let (_, pt4_rest2) = pt4_rest.split_at(127);
        let (pt4_at_384, pt4_rest3) = pt4_rest2.split_at(1);
        // Isolate PML4[511]
        let (_, mut pt4_at_511) = pt4_rest3.split_at(126);

        let linear_mapping = Self::setup_linear_mapping_ptes(&frame_alloc, &mut pt4_at_256);

        let (entry, mut pt1_static, stack, kernel_static) = Self::setup_static_ptes(
            &frame_alloc,
            &mut pt4_at_511,
            &mut phys_mem.static_region,
            kernel,
            kernel_n_huge_pages,
        );

        let boot_info_frame = frame_alloc.alloc_frame().unwrap();

        // All frame allocations done — record pre_allocated count
        let pre_allocated = frame_alloc.frames_allocated();

        let boot_info_virt = Self::setup_boot_info(
            &mut pt1_static,
            boot_info_frame,
            phys_mem,
            linear_mapping,
            kernel_static,
            pt4_at_384.virt_range(),
            pre_allocated,
        );

        Self {
            pt4: pt4_address,
            entry,
            stack_top: stack.end,
            boot_info: boot_info_virt,
        }
    }

    fn setup_linear_mapping_ptes<'a>(
        frame_alloc: &BumpFrameAllocator<'a>,
        pt4: &mut AllocatingPageTable<'a>,
    ) -> Range<VirtAddr> {
        let span = span!(Level::TRACE, "AddressSpaceState.setup_linear_mapping_ptes");
        let _enter = span.enter();

        let pt3_frame = frame_alloc.alloc_frame().unwrap();
        let mut pt3 = pt4
            .allocate_pte(pt3_frame, Self::general_flags())
            .unwrap();

        let pt2_frame = frame_alloc.alloc_frame().unwrap();
        let mut pt2 = pt3
            .allocate_pte(pt2_frame, Self::general_flags())
            .unwrap();

        let mut phys = PhysAddr::new(0);
        while phys.as_u64() < PhysicalMemory::total_phys_size() {
            pt2.allocate(phys, Self::phys_mapping_flags() | pte::PageTableFlags::HUGE)
                .unwrap();
            phys += L1_HUGE_PAGE_SIZE as u64;
        }

        pt2.virt_range()
    }

    fn setup_static_ptes<'a>(
        frame_alloc: &BumpFrameAllocator<'a>,
        pt4_at_511: &mut AllocatingPageTable<'a>,
        static_region: &mut PhysicalRegion,
        kernel: &loader::KernelBinary,
        kernel_n_huge_pages: usize,
    ) -> (VirtAddr, AllocatingPageTable<'a>, Range<VirtAddr>, Range<VirtAddr>) {
        let span = span!(Level::TRACE, "AddressSpaceState.setup_static_ptes");
        let _enter = span.enter();

        let pt3_frame = frame_alloc.alloc_frame().unwrap();
        let pt3 = pt4_at_511
            .allocate_pte(pt3_frame, Self::general_flags())
            .unwrap();
        // PT3[510] -> PT2, virt_base = 0xFFFF_FFFF_8000_0000
        let (_, mut pt3_at_510) = pt3.split_at(510);

        let pt2_frame = frame_alloc.alloc_frame().unwrap();
        let mut pt2 = pt3_at_510
            .allocate_pte(pt2_frame, Self::general_flags())
            .unwrap();

        let static_block = static_region.into_guest_phys();
        let entry = Self::setup_kernel(static_block, kernel_n_huge_pages, &mut pt2, kernel);

        // PT1 for stack + boot_info (4K pages), placed after kernel binary huge pages
        let pt1_frame = frame_alloc.alloc_frame().unwrap();
        let mut pt1 = pt2
            .allocate_pte(pt1_frame, Self::stack_flags() | Self::boot_info_flags())
            .unwrap();

        let stack = Self::setup_stack(&mut pt1, frame_alloc);
        let static_virt = pt2.virt_range();

        (entry, pt1, stack, static_virt)
    }

    fn setup_kernel(
        mut static_block: GuestPhysBlock<'_, DynamicSize, Alignment<L1_HUGE_PAGE_SIZE>>,
        n_huge_pages: usize,
        pt2: &mut AllocatingPageTable,
        kernel: &loader::KernelBinary,
    ) -> VirtAddr {
        let span = span!(Level::TRACE, "AddressSpaceState.setup_kernel");
        let _enter = span.enter();

        let (binary_chunks, _) = static_block
            .chunk_by_fixed_aligned::<L1_HUGE_PAGE_SIZE>()
            .split_at(n_huge_pages);

        for chunk in binary_chunks {
            pt2.allocate(
                chunk.begin(),
                Self::kernel_flags() | pte::PageTableFlags::HUGE,
            )
            .unwrap();
        }

        let kernel_base = pt2.virt_range().start;
        let memory = unsafe { &mut *static_block.as_uninit_ptr_mut() };
        kernel.load_at(memory, kernel_base);

        kernel.entry_virt(kernel_base)
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
            let virt = pt1.allocate(frame.begin(), Self::stack_flags()).unwrap();
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
        frame: L0GuestFrame,
        phys_mem: &PhysicalMemory,
        linear_mapping: Range<VirtAddr>,
        kernel_static: Range<VirtAddr>,
        kernel_dynamic: Range<VirtAddr>,
        pre_allocated: u64,
    ) -> VirtAddr {
        let span = span!(Level::TRACE, "AddressSpaceState.setup_bootinfo");
        let _enter = span.enter();

        let virt = pt1
            .allocate(frame.begin(), Self::boot_info_flags())
            .unwrap();

        let static_phys = phys_mem.static_region.phys_range();
        let kernel_dyn_phys = phys_mem.kernel_dynamic_region.phys_range();
        let user_phys = phys_mem.user_region.phys_range();

        let phys_to_virt = |phys_base: PhysAddr| linear_mapping.start + phys_base.as_u64();

        let static_mapping =
            protocol::LinearPhysMapping::new(static_phys.clone(), phys_to_virt(static_phys.start))
                .unwrap();
        let kernel_dyn_mapping = protocol::LinearPhysMapping::new(
            kernel_dyn_phys.clone(),
            phys_to_virt(kernel_dyn_phys.start),
        )
        .unwrap();
        let user_mapping = protocol::LinearPhysMapping::new(
            user_phys.clone(),
            phys_to_virt(user_phys.start),
        )
        .unwrap();

        let boot_info = protocol::BootInfo {
            logging_port: LOG_PORT,
            event_port: EVENT_PORT,
            physical_memory: protocol::PhysicalMemory {
                static_region: static_mapping,
                kernel_dynamic_region: protocol::PhysMemPool {
                    mapping: kernel_dyn_mapping,
                    pre_allocated,
                },
                user_region: protocol::PhysMemPool {
                    mapping: user_mapping,
                    pre_allocated: 0,
                },
            },
            virtual_layout: protocol::VirtualLayout {
                linear_mapping: Self::region_from_range(linear_mapping),
                kernel_static: Self::region_from_range(kernel_static),
                kernel_dynamic: Self::region_from_range(kernel_dynamic),
            },
            salt: 0xDEADBEEF,
        };

        let bytes = frame.into_page_mut().bytes_mut();
        unsafe { (bytes.as_ptr() as *mut protocol::BootInfo).write(boot_info) };

        virt
    }

    fn region_from_range(range: Range<VirtAddr>) -> protocol::VirtRegion {
        protocol::VirtRegion {
            base: range.start,
            size: range.end - range.start,
        }
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
    sregs.efer |= (1 << 0) | (1 << 8) | (1 << 10) | (1 << 11); // Syscall|LME|LMA|NXE

    vcpu.set_sregs(&sregs).unwrap();
}

fn setup_vm(kvm: &Kvm, kernel_binary: &str) -> (VmFd, VcpuFd, PhysicalMemory) {
    let span = span!(Level::TRACE, "AddressSpaceState.setup_vm");
    let _enter = span.enter();
    let vm = kvm.create_vm().unwrap();
    // maybe not needed actually?
    // https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt says that
    // > This is needed on Intel hardware
    // > because of a quirk in the virtualization implementation
    vm.set_tss_address(0xfffbd000).unwrap();
    vm.set_identity_map_address(0xffffc000).unwrap();

    let mut pit_config = kvm_pit_config::default();
    pit_config.flags = KVM_PIT_SPEAKER_DUMMY;

    vm.create_pit2(pit_config).unwrap();
    vm.create_irq_chip().unwrap();

    let mut elf_data = Vec::new();
    File::open(kernel_binary)
        .unwrap()
        .read_to_end(&mut elf_data)
        .unwrap();
    let kernel = loader::KernelBinary::from_binary(&elf_data);

    let mut phys_mem = PhysicalMemory::setup(&vm);
    let address_space = AddressSpaceState::setup(&mut phys_mem, &kernel);

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

    (vm, vcpu, phys_mem)
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

    let (vm, mut vcpu_fd, phys_mem) = setup_vm(&kvm, &path_to_kernel_binary);

    let mut collector = KernelLogCollector::new();

    loop {
        let exit_reason = match vcpu_fd.run() {
            Err(errno) => {
                error!(errno = %errno, "VCpu.Run failed:");
                panic!("vcpu_fd.run() failed");
            }
            Ok(exit_reason) => exit_reason,
        };
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
                let dirty_pages_bitmap = vm
                    .get_dirty_log(0, PhysicalMemory::STATIC_REGION_SIZE)
                    .unwrap();
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

    let _ = phys_mem; // Call unmap;
}

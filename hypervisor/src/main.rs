use core::slice;
use std::{env, fs::File, io::Read, mem, ptr::null_mut};

use kvm_bindings::{KVM_MEM_LOG_DIRTY_PAGES, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};

use arch_x86_64::{protocol, pte};
use goblin::elf::{Elf, program_header};
use nix::libc;

// TODO: unwrap -> anyhow or something similar

const MEM_SIZE: usize = 6 * 1024 * 1024;
const STACK_TOP: u64 = 4 * 1024 * 1024;

fn load_kernel_elf(mem: &mut [u8], elf_data: &[u8]) -> u64 {
    let elf = Elf::parse(&elf_data).unwrap();
    for header in &elf.program_headers {
        if header.p_type != program_header::PT_LOAD {
            continue;
        }

        let file_offset = header.p_offset as usize;
        let file_size = header.p_filesz as usize;
        let mem_size = header.p_memsz as usize;
        let dst = header.p_vaddr as usize;

        // TODO: add checks that mem is big enough

        assert!(dst > 0x4000); // checks that we didn't override page tables
        mem[dst..dst + file_size].copy_from_slice(&elf_data[file_offset..file_offset + file_size]);
        if mem_size > file_size {
            mem[dst + file_size..dst + mem_size].fill(0);
        }
    }

    elf.entry
}

fn setup_physical_memory(vm: &VmFd) -> &mut [u8] {
    let memory_ptr = unsafe {
        libc::mmap(
            null_mut(),
            MEM_SIZE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        ) as *mut u8
    };
    let memory_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: MEM_SIZE as u64,
        userspace_addr: memory_ptr as u64,
        flags: KVM_MEM_LOG_DIRTY_PAGES,
    };
    unsafe { vm.set_user_memory_region(memory_region).unwrap() };
    unsafe { slice::from_raw_parts_mut(memory_ptr, MEM_SIZE) }
}

fn setup_virtual_table(mem: &mut [u8]) -> u64 {
    use pte::PageTableFlags as fs;
    const PAGE_TABLE_4: usize = 0x1000;
    const PAGE_TABLE_3: usize = 0x2000;
    const PAGE_TABLE_2: usize = 0x3000;

    let memory_ptr = mem.as_ptr();
    let mapping_flags = fs::PRESENT | fs::WRITABLE | fs::EXECUTABLE;

    let pt4: &mut pte::PageTable = unsafe {
        slice::from_raw_parts_mut(
            (memory_ptr.add(PAGE_TABLE_4)) as *mut _,
            pte::PAGE_TABLE_ENTRY_COUNT,
        )
    }
    .try_into()
    .unwrap();
    for pte in pt4.iter_mut() {
        *pte = pte::PageTableEntry::non_present();
    }
    pt4[0] = pte::PageTableEntry::new(PAGE_TABLE_3, mapping_flags);

    let pt3: &mut pte::PageTable = unsafe {
        slice::from_raw_parts_mut(
            (memory_ptr.add(PAGE_TABLE_3)) as *mut _,
            pte::PAGE_TABLE_ENTRY_COUNT,
        )
    }
    .try_into()
    .unwrap();
    for pte in pt3.iter_mut() {
        *pte = pte::PageTableEntry::non_present();
    }
    pt3[0] = pte::PageTableEntry::new(PAGE_TABLE_2, mapping_flags);

    let pt2: &mut pte::PageTable = unsafe {
        slice::from_raw_parts_mut(
            (memory_ptr.add(PAGE_TABLE_2)) as *mut _,
            pte::PAGE_TABLE_ENTRY_COUNT,
        )
    }
    .try_into()
    .unwrap();
    for pte in pt2.iter_mut() {
        *pte = pte::PageTableEntry::non_present();
    }
    pt2[0] = pte::PageTableEntry::new(0x0, mapping_flags | fs::HUGE);
    pt2[1] = pte::PageTableEntry::new(0x200000, mapping_flags | fs::HUGE);
    pt2[2] = pte::PageTableEntry::new(0x400000, mapping_flags | fs::HUGE);

    PAGE_TABLE_4 as u64
}

fn setup_sregs(vcpu: &VcpuFd, pt4: u64) {
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
    sregs.cr3 = pt4 as u64;
    sregs.cr4 |= 1 << 5; // PAE
    sregs.cr0 |= 1 << 0; // PE
    sregs.cr0 |= 1 << 31; // PG
    sregs.efer |= (1 << 8) | (1 << 10); // LME|LMA

    vcpu.set_sregs(&sregs).unwrap();
}

fn setup_vm(kvm: &Kvm, kernel_binary: &str) -> (VmFd, VcpuFd) {
    let vm = kvm.create_vm().unwrap();
    // maybe not needed actually?
    // https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt says that
    // > This is needed on Intel hardware
    // > because of a quirk in the virtualization implementation
    vm.set_tss_address(0xfffbd000).unwrap();
    vm.set_identity_map_address(0xffffc000).unwrap();

    let memory = setup_physical_memory(&vm);

    // TODO: guarantee that binary will not overlap with page tables
    let mut kernel_elf = File::open(kernel_binary).unwrap();
    let mut elf_data = Vec::new();
    kernel_elf.read_to_end(&mut elf_data).unwrap();
    let entry = load_kernel_elf(memory, &elf_data);

    let pt4 = setup_virtual_table(memory);

    let vcpu = vm.create_vcpu(0).unwrap();
    let mut cpuid = kvm
        .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .unwrap();
    vcpu.set_cpuid2(&mut cpuid).unwrap();

    setup_sregs(&vcpu, pt4);

    let mut regs = vcpu.get_regs().unwrap();
    regs.rip = entry;
    regs.rsp = STACK_TOP;
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
        if byte == '\n' as u8 {
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
    let path_to_kernel_binary = env::args().nth(1).unwrap();

    let kvm = Kvm::new().unwrap();

    let (vm, mut vcpu_fd) = setup_vm(&kvm, &path_to_kernel_binary);

    let mut collector = KernelLogCollector::new();

    loop {
        match vcpu_fd.run().expect("run failed") {
            VcpuExit::IoIn(addr, data) => {
                println!(
                    "Received an I/O in exit. Address: {:#x}. Data: {:#x}",
                    addr, data[0],
                );
            }
            VcpuExit::IoOut(addr, data) => {
                if addr == protocol::LOG_PORT {
                    collector.add_bytes(data);
                } else {
                    println!(
                        "Received an I/O out exit. Address: {:#x}. Data: {:#x}",
                        addr, data[0],
                    );
                }
            }
            VcpuExit::MmioRead(addr, _data) => {
                println!("Received an MMIO Read Request for the address {:#x}.", addr,);
            }
            VcpuExit::MmioWrite(addr, _data) => {
                println!("Received an MMIO Write Request to the address {:#x}.", addr,);
                let dirty_pages_bitmap = vm.get_dirty_log(0, MEM_SIZE).unwrap();
                let dirty_pages = dirty_pages_bitmap
                    .into_iter()
                    .map(|page| page.count_ones())
                    .fold(0, |dirty_page_count, i| dirty_page_count + i);
                assert_eq!(dirty_pages, 1);
            }
            VcpuExit::Hlt => {
                break;
            }
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

use std::{cmp, mem::MaybeUninit, ops::Range};

use arch_x86_64::addr::{PhysAddr, VirtAddr};
use arch_x86_64::frage::L0Page;
use goblin::elf::{program_header, reloc, Elf};

pub struct KernelBinary<'a> {
    binary: &'a [u8],
    pub elf: Elf<'a>,
}

impl<'a> KernelBinary<'a> {
    pub fn from_binary(binary: &'a [u8]) -> Self {
        Self {
            binary,
            elf: Elf::parse(binary).unwrap(),
        }
    }

    pub fn needed_memory(&self) -> Option<Range<PhysAddr>> {
        let needed_range = self
            .elf
            .program_headers
            .iter()
            .filter(|h| h.p_type == program_header::PT_LOAD)
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

    pub fn load_at(&self, mem: &mut [MaybeUninit<u8>], load_virt_base: u64) {
        self.load_segments(mem);
        self.apply_relocations(mem, load_virt_base);
    }

    fn load_segments(&self, mem: &mut [MaybeUninit<u8>]) {
        for header in &self.elf.program_headers {
            if header.p_type != program_header::PT_LOAD {
                continue;
            }

            let file_offset = header.p_offset as usize;
            let file_size = header.p_filesz as usize;
            let mem_size = header.p_memsz as usize;
            let dst = header.p_vaddr as usize;

            mem[dst..dst + file_size]
                .write_copy_of_slice(&self.binary[file_offset..file_offset + file_size]);
            if mem_size > file_size {
                mem[dst + file_size..dst + mem_size].write_filled(0);
            }
        }
    }

    fn apply_relocations(&self, mem: &mut [MaybeUninit<u8>], load_virt_base: u64) {
        for rela in &self.elf.dynrelas {
            match rela.r_type {
                reloc::R_X86_64_RELATIVE => {
                    let offset = rela.r_offset as usize;
                    let value = load_virt_base.wrapping_add(rela.r_addend.unwrap_or(0) as u64);
                    let dest = mem[offset..offset + 8].as_mut_ptr() as *mut u64;
                    unsafe { dest.write_unaligned(value) };
                }
                other => panic!("unexpected relocation type {other} at offset {:#x}", rela.r_offset),
            }
        }
    }

    pub fn entry_virt(&self, load_virt_base: u64) -> VirtAddr {
        VirtAddr::new(load_virt_base + self.elf.entry)
    }
}

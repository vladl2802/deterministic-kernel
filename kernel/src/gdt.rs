use arch_x86_64::{
    instructions::segmentation::{CS, SS, Segment},
    instructions::tables,
    structures::gdt::{Descriptor, GlobalDescriptorTable},
    structures::tss::TaskStateSegment,
};
use crate::late_init::LateInit;

static GDT: LateInit<GlobalDescriptorTable> = LateInit::new();

pub fn init(tss: &'static TaskStateSegment) {
    let mut gdt = GlobalDescriptorTable::new();
    let code = gdt.append(Descriptor::kernel_code_segment());
    let data = gdt.append(Descriptor::kernel_data_segment());
    let tss_sel = gdt.append(Descriptor::tss_segment(tss));
    unsafe { GDT.finish_init(gdt); }
    unsafe {
        GDT.load();
        CS::set_reg(code);
        SS::set_reg(data);
        tables::load_tss(tss_sel);
    }
}

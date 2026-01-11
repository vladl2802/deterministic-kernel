pub trait AlignMarker<const ALIGN: usize> {
    const ALIGN: usize = ALIGN;

    type Marker;
}

#[macro_use]
pub mod macros {
    #[macro_export]
    macro_rules! define_align {
        ($name:ident, $origin:ident, $align:literal, $expected:expr) => {
            define_align!($name, $origin, $align);

            const _: () = assert!($align == $expected);
        };
        ($name:ident, $origin:ident, $align:literal) => {
            #[repr(C, align($align))]
            #[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
            pub struct $name;

            impl $name {
                pub const ALIGN: usize = $align;
            }

            impl crate::align_marker::AlignMarker<$align> for $origin {
                const ALIGN: usize = $align;

                type Marker = $name;
            }
        };
    }
}

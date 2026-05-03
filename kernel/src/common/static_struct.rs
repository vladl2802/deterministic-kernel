use super::LateInit;

pub unsafe trait StaticStructWrapper {
    type UnderlyingT: 'static;
    const UNDERLYING_REF: &'static LateInit<Self::UnderlyingT>;

    fn finish_init(underlying: Self::UnderlyingT) {
        unsafe { Self::UNDERLYING_REF.finish_init(underlying) };
    }

    fn get() -> &'static Self::UnderlyingT {
        Self::UNDERLYING_REF.as_ref()
    }

    fn me() -> Self;
}

macro_rules! declare_static_struct {
    ($vis:vis $mod_name:ident => $struct_name:ident = $impl_ty:ty) => {
        mod $mod_name {
            use super::*;

            static STATIC: $crate::common::LateInit<$impl_ty> = $crate::common::LateInit::new();

            $vis struct $struct_name;

            unsafe impl $crate::common::StaticStructWrapper for $struct_name {
                type UnderlyingT = $impl_ty;
                const UNDERLYING_REF: &'static $crate::common::LateInit<Self::UnderlyingT> =
                    &STATIC;

                fn me() -> Self {
                    Self {}
                }
            }
        }
    };
}

pub(crate) use declare_static_struct;

#[macro_use]
mod assert_alignment {
    #[macro_export]
    macro_rules! assert_alignment {
        ($expr:expr) => {{
            let (pref, mid, suff) = $expr;
            assert_eq!((pref.len(), suff.len()), (0, 0));
            mid
        }};
    }

    #[macro_export]
    macro_rules! debug_assert_alignment {
        ($expr:expr) => {{
            let (pref, mid, suff) = $expr;
            debug_assert_eq!((pref.len(), suff.len()), (0, 0));
            mid
        }};
    }

    #[macro_export]
    macro_rules! try_alignment {
        ($expr:expr) => {{
            let (pref, mid, suff) = $expr;
            if (pref.len(), suff.len()) == (0, 0) {
                ::core::option::Option::Some(mid)
            } else {
                ::core::option::Option::None
            }
        }};
    }
}

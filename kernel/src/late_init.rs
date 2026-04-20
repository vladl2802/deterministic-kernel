use core::{any, cell::UnsafeCell, fmt, ops, ptr};

pub struct LateInit<T> {
    underlying: UnsafeCell<Option<T>>,
}

struct ShortDebugForm<'a, T>(&'a LateInit<T>);

unsafe impl<T> Sync for LateInit<T> {}

impl<T> LateInit<T> {
    pub const fn new() -> Self {
        Self {
            underlying: UnsafeCell::new(None),
        }
    }

    pub unsafe fn finish_init(&self, underlying: T) {
        assert!(
            unsafe { self.option() }.is_none(),
            "finish_init called second time on object ({})",
            self.short_debug_form(),
        );

        *unsafe { &mut *self.underlying.get() } = Some(underlying);
    }

    unsafe fn option(&self) -> &Option<T> {
        unsafe { &*self.underlying.get() }
    }

    #[track_caller]
    fn underlying_ref(&self) -> &T {
        let underlying = unsafe { self.option() };
        debug_assert!(
            underlying.is_some(),
            "underlying is not initialized in object ({})",
            self.short_debug_form()
        );

        unsafe { underlying.as_ref().unwrap_unchecked() }
    }

    #[track_caller]
    fn underlying_mut(&mut self) -> &mut T {
        let underlying = self.underlying.get_mut();
        debug_assert!(
            underlying.is_some(),
            "underlying is not initialized in object ({})",
            self.short_debug_form()
        );
        let underlying = self.underlying.get_mut();

        unsafe { underlying.as_mut().unwrap_unchecked() }
    }

    fn short_debug_form(&self) -> ShortDebugForm<'_, T> {
        ShortDebugForm(self)
    }
}

impl<T> AsRef<T> for LateInit<T> {
    #[track_caller]
    fn as_ref(&self) -> &T {
        self.underlying_ref()
    }
}

impl<T> AsMut<T> for LateInit<T> {
    #[track_caller]
    fn as_mut(&mut self) -> &mut T {
        self.underlying_mut()
    }
}

impl<T> ops::Deref for LateInit<T> {
    type Target = T;

    #[track_caller]
    fn deref(&self) -> &Self::Target {
        self.underlying_ref()
    }
}

impl<T> ops::DerefMut for LateInit<T> {
    #[track_caller]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.underlying_mut()
    }
}

impl<'a, T> fmt::Display for ShortDebugForm<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"addr", &ptr::from_ref(self))
            .entry(&"type", &any::type_name::<T>())
            .finish()
    }
}

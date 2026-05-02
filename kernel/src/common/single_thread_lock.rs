use core::{
    any,
    cell::{Cell, UnsafeCell},
    fmt, ptr,
};

use arch_x86_64::instructions::interrupts;

pub struct SingleThreadLock<T> {
    locked: Cell<bool>,
    underlying: UnsafeCell<T>,
}

struct ShortDebugForm<'a, T>(&'a SingleThreadLock<T>);

// Because it is single-threaded we do not need any syncronization
unsafe impl<T> Send for SingleThreadLock<T> {}
unsafe impl<T> Sync for SingleThreadLock<T> {}

impl<T> SingleThreadLock<T> {
    pub const fn new_unlocked(underlying: T) -> Self {
        Self {
            locked: Cell::new(false),
            underlying: UnsafeCell::new(underlying),
        }
    }

    #[track_caller]
    pub fn lock(&self) {
        if self.locked.replace(true) {
            panic!(
                "Lock on already locked object ({})",
                self.short_debug_form()
            );
        }
    }

    #[track_caller]
    pub fn unlock(&self) {
        if !self.locked.replace(false) {
            panic!(
                "Unlock on already unlocked object ({})",
                self.short_debug_form()
            )
        }
    }

    #[track_caller]
    pub fn with_lock<R>(&self, body: impl FnOnce(&mut T) -> R) -> R {
        interrupts::without_interrupts(|| {
            self.lock();
            // Kernel is in panic=abort mode. If body panics we immediately exit into panic handler.
            // If panic handler panics its okay, code there shouldn't be sensetive to it.
            let result = body(unsafe { &mut *self.underlying.get() });
            self.unlock();
            result
        })
    }

    fn short_debug_form(&self) -> ShortDebugForm<'_, T> {
        ShortDebugForm(self)
    }
}

impl<'a, T> fmt::Display for ShortDebugForm<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"addr", &ptr::from_ref(self.0))
            .entry(&"type", &any::type_name::<T>())
            .finish()
    }
}

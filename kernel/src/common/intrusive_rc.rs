use core::{cell::Cell, marker, pin::Pin, ptr::{self, NonNull}};

use super::marker as common_marker;

pub trait RcStored: 'static {
    // Called on the Rc that will be destructed in a moment
    // prev and next are former neighbours of the current value
    fn on_drop(&mut self, prev: Option<&Self>, next: Option<&Self>);
}

#[derive(Debug)]
struct Link<T: RcStored> {
    next: Cell<Option<NonNull<IntrusiveRcStorage<T>>>>,
    prev: Cell<Option<NonNull<IntrusiveRcStorage<T>>>>,
}

impl<T: RcStored> Link<T> {
    fn new() -> Self {
        Self { next: Cell::new(None), prev: Cell::new(None) }
    }

    fn is_linked(&self) -> bool {
        self.next.get().is_some() || self.prev.get().is_some()
    }

    fn set_next_raw(&self, v: Option<NonNull<IntrusiveRcStorage<T>>>) {
        self.next.set(v);
    }

    fn set_prev_raw(&self, v: Option<NonNull<IntrusiveRcStorage<T>>>) {
        self.prev.set(v);
    }
}

#[derive(Debug)]
pub struct IntrusiveRcStorage<T: RcStored> {
    value: T,
    link: Link<T>,
    _unpin: marker::PhantomPinned,
    _unsync: marker::PhantomData<common_marker::Unsync>,
}

impl<T: RcStored> IntrusiveRcStorage<T> {
    pub fn new_unlinked(value: T) -> Self {
        Self {
            value,
            link: Link::new(),
            _unpin: marker::PhantomPinned,
            _unsync: marker::PhantomData,
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn is_linked(&self) -> bool {
        self.link.is_linked()
    }

    pub fn get_next(&self) -> Option<Pin<&Self>> {
        let ptr = self.link.next.get()?;
        Some(unsafe { Pin::new_unchecked(ptr.as_ref()) })
    }

    pub fn get_prev(&self) -> Option<Pin<&Self>> {
        let ptr = self.link.prev.get()?;
        Some(unsafe { Pin::new_unchecked(ptr.as_ref()) })
    }

    fn set_next(self: Pin<&Self>, next: Option<Pin<&Self>>) {
        if let Some(next) = next {
            assert!(!ptr::eq(self.get_ref(), next.get_ref()));
            self.link.set_next_raw(Some(NonNull::from_ref(next.get_ref())));
        } else {
            self.link.set_next_raw(None);
        }
    }

    fn set_prev(self: Pin<&Self>, prev: Option<Pin<&Self>>) {
        if let Some(prev) = prev {
            assert!(!ptr::eq(self.get_ref(), prev.get_ref()));
            self.link.set_prev_raw(Some(NonNull::from_ref(prev.get_ref())));
        } else {
            self.link.set_prev_raw(None);
        }
    }

    // Links self after other
    pub unsafe fn link_to(self: Pin<&Self>, other: Pin<&Self>) {
        assert!(!self.link.is_linked());
        assert!(!ptr::eq(self.get_ref(), other.get_ref()));
        let old_next = other.get_next();

        self.set_prev(Some(other));
        self.set_next(old_next);

        old_next.map(|old_next| old_next.set_prev(Some(self)));

        other.set_next(Some(self));
    }

    fn unlink(&self) {
        assert!(self.is_linked());
        let prev = self.get_prev();
        let next = self.get_next();

        if let Some(prev) = prev {
            prev.set_next(next);
        }
        if let Some(next) = next {
            next.set_prev(prev);
        }

        self.link.set_next_raw(None);
        self.link.set_next_raw(None);
    }
}

impl<T: RcStored> Drop for IntrusiveRcStorage<T> {
    fn drop(&mut self) {
        let prev_ptr = self.link.prev.get();
        let next_ptr = self.link.next.get();

        self.unlink();

        let prev = prev_ptr.map(|p| unsafe { p.as_ref() }.value());
        let next = next_ptr.map(|p| unsafe { p.as_ref() }.value());

        self.value.on_drop(prev, next);
    }
}

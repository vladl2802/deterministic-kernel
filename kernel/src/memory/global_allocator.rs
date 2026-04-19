use core::{
    alloc::{GlobalAlloc, Layout},
    any,
    cell::{Cell, UnsafeCell},
    ptr,
};

use buddy_system_allocator::Heap;

struct SingleThreadLock<T> {
    locked: Cell<bool>,
    underlying: UnsafeCell<T>,
}

// Because it is single-threaded we do not need any syncronization
unsafe impl<T> Send for SingleThreadLock<T> {}
unsafe impl<T> Sync for SingleThreadLock<T> {}

impl<T> SingleThreadLock<T> {
    const fn new_unlocked(underlying: T) -> Self {
        Self {
            locked: Cell::new(false),
            underlying: UnsafeCell::new(underlying),
        }
    }

    #[track_caller]
    fn lock(&self) {
        if self.locked.replace(true) {
            panic!(
                "Lock on already locked object (addr = {:p}, type = {})",
                ptr::from_ref(self),
                any::type_name::<T>(),
            );
        }
    }

    #[track_caller]
    fn unlock(&self) {
        if !self.locked.replace(false) {
            panic!(
                "Unlock on already unlocked object (addr = {:p}, type = {})",
                ptr::from_ref(self),
                any::type_name::<T>(),
            )
        }
    }

    #[track_caller]
    fn with_lock<R>(&self, body: impl FnOnce(&mut T) -> R) -> R {
        self.lock();
        let result = body(unsafe { &mut *self.underlying.get() });
        self.unlock();
        result
    }
}

type Allocator = Heap<32>;

struct LockedHeap(SingleThreadLock<Option<Allocator>>);

impl LockedHeap {
    fn finish_init(&self, alloc: Allocator) {
        self.0.with_lock(|underlying| {
            *underlying = Some(alloc);
        });
    }

    fn with_allocator<R>(&self, body: impl FnOnce(&mut Allocator) -> R) -> R {
        self.0.with_lock(|alloc| {
            let alloc = alloc.as_mut().expect("alloc not initialized");
            body(alloc)
        })
    }
}

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.with_allocator(|alloc| alloc.alloc(layout))
            .map_or(ptr::null_mut(), |p| p.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let ptr = unsafe { ptr::NonNull::new_unchecked(ptr) };
        self.with_allocator(|alloc| unsafe { alloc.dealloc(ptr, layout) });
    }
}

#[alloc_error_handler]
#[cold]
#[inline(never)]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("failed to allocate memory, layout = {:?}", layout)
}

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap(SingleThreadLock::new_unlocked(None));

pub fn init(heap_start: usize, heap_size: usize) {
    let mut heap = Heap::empty();
    unsafe { heap.init(heap_start, heap_size) };
    ALLOCATOR.finish_init(heap);
}

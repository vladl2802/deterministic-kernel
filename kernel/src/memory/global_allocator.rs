use core::{
    alloc::{GlobalAlloc, Layout},
    ptr,
};

use crate::common::{LateInit, SingleThreadLock};

use buddy_system_allocator::Heap;

type Allocator = Heap<32>;

struct LockedHeap(LateInit<SingleThreadLock<Allocator>>);

impl LockedHeap {
    fn finish_init(&self, alloc: Allocator) {
        unsafe { self.0.finish_init(SingleThreadLock::new_unlocked(alloc)) };
    }

    fn with_allocator<R>(&self, body: impl FnOnce(&mut Allocator) -> R) -> R {
        self.0.with_lock(body)
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
static ALLOCATOR: LockedHeap = LockedHeap(LateInit::new());

pub fn init(heap_start: usize, heap_size: usize) {
    let mut heap = Heap::empty();
    unsafe { heap.init(heap_start, heap_size) };
    ALLOCATOR.finish_init(heap);
}

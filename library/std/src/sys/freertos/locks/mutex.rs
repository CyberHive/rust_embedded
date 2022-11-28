use crate::hint;
use crate::sync::atomic::{AtomicBool, Ordering};

pub struct Mutex {
    is_acquired: AtomicBool,
}

// Mutex new function needs to be const_stable. Unfortunately that means it can't be extern
// and we can't modify and use the one in the FreeRTOS Rust bindings.
// This precludes using FreeRTOS mutex here - hence the implementation using AtomicBool

pub type MovableMutex = Mutex;

unsafe impl Send for Mutex {}
unsafe impl Sync for Mutex {}

impl Mutex {
    #[inline]
    #[rustc_const_stable(feature = "const_locks", since = "1.63.0")]
    pub const fn new() -> Mutex {
        Mutex { is_acquired: AtomicBool::new(false) }
    }

    // AtomicBool::swap() has a similar truth table to 'TestAndSet', making it a suitable basis
    // for mutex primitives.
    //    Original value     New value     return
    //    ---------------------------------------
    //    false              true          false
    //    true               true          true
    //
    // The lock function uses AtomicBool::swap() to atomically set the is_acquired flag, and
    // find out whether it was previously already set. That way, in the same atomic operation,
    // we can either take the mutex lock or find out that it is already taken by another task.
    #[inline]
    pub unsafe fn lock(&self) {
        while self.is_acquired.swap(true, Ordering::AcqRel) {
            hint::spin_loop;
        }
    }

    // unlock() simply clears the is_aquired flag to release the lock.
    #[inline]
    pub unsafe fn unlock(&self) {
        //Check it is already locked, otherwise we're trying to unlock an already unlocked mutex
        assert_eq!(self.is_acquired.load(Ordering::Relaxed), true);

        //Unlock
        self.is_acquired.store(false, Ordering::Release);
    }

    // try-lock uses the same logic as lock(), but returns the success status insteadof waiting
    // for successful locking.
    #[inline]
    pub unsafe fn try_lock(&self) -> bool {
        if self.is_acquired.swap(true, Ordering::AcqRel) { false } else { true }
    }
}

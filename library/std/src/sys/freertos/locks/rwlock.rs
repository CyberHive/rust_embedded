use crate::cell::Cell;

pub struct RwLock {
    // Cell is not an appropriate implementation for a multitasking platform.
    // Added panics to make this blow up if it is used. Long term, we need to use FreeRTOS mutexes or semaphores.
    mode: Cell<isize>,
}

pub type MovableRwLock = RwLock;

unsafe impl Send for RwLock {}
unsafe impl Sync for RwLock {} // no threads on this platform

impl RwLock {
    #[inline]
    #[rustc_const_stable(feature = "const_locks", since = "1.63.0")]
    pub const fn new() -> RwLock {
        RwLock { mode: Cell::new(0) }
    }

    #[inline]
    pub unsafe fn read(&self) {
        panic!("rwlock Not implemented for FreeRTOS");
        let m = self.mode.get();
        if m >= 0 {
            self.mode.set(m + 1);
        } else {
            rtabort!("rwlock locked for writing");
        }
    }

    #[inline]
    pub unsafe fn try_read(&self) -> bool {
        panic!("rwlock Not implemented for FreeRTOS");
        let m = self.mode.get();
        if m >= 0 {
            self.mode.set(m + 1);
            true
        } else {
            false
        }
    }

    #[inline]
    pub unsafe fn write(&self) {
        panic!("rwlock Not implemented for FreeRTOS");
        if self.mode.replace(-1) != 0 {
            rtabort!("rwlock locked for reading")
        }
    }

    #[inline]
    pub unsafe fn try_write(&self) -> bool {
        panic!("rwlock Not implemented for FreeRTOS");
        if self.mode.get() == 0 {
            self.mode.set(-1);
            true
        } else {
            false
        }
    }

    #[inline]
    pub unsafe fn read_unlock(&self) {
        panic!("rwlock Not implemented for FreeRTOS");
        self.mode.set(self.mode.get() - 1);
    }

    #[inline]
    pub unsafe fn write_unlock(&self) {
        panic!("rwlock Not implemented for FreeRTOS");
        assert_eq!(self.mode.replace(0), -1);
    }
}

use crate::cell::Cell;
use crate::sync::Mutex;

// rwlock allows:
// - one writer
// - any number of readers
// rwlock prevents:
// - concurrent reader(s) and writer
// - more than one writer
//
// Allowed permutations:
// Number of Readers    Number of Writers    mode
//        0                    0              0
//      1...n                  0            1...n
//        0                    1             -1
// The 'mode' internal state variable encapsulates the reader and writer state into a single quantity,
// as tabulated above

// Implementation uses a Cell for the mode state variable.
// Because Cell is not thread-safe, all logic to check and manipulate it needs to be Mutex protected.
pub struct RwLock {
    mode: Mutex<Cell<isize>>,
}

pub type MovableRwLock = RwLock;

unsafe impl Send for RwLock {}
unsafe impl Sync for RwLock {} // no threads on this platform

impl RwLock {
    #[inline]
    #[rustc_const_stable(feature = "const_locks", since = "1.63.0")]
    pub const fn new() -> RwLock {
        RwLock { mode: Mutex::new(Cell::new(0)) }
    }

    #[inline]
    pub fn read(&self) {
        // Repeat until the lock is obtained
        loop {
            // Get the mutex for exclusive access to 'mode'
            let mut mode = self.mode.lock().unwrap();

            let cur_val = mode.get();
            // If value is 0 (unlocked) or >0 (read locked), increment to add another read lock
            if cur_val >= 0 {
                mode.set(cur_val + 1);
                return; // success setting a read lock
            }
            // Mutex is unlocked by going out of scope
        }
    }

    #[inline]
    pub fn try_read(&self) -> bool {
        // Get the mutex for exclusive access to 'mode'
        let mut mode = self.mode.lock().unwrap();

        // If value is 0 (unlocked) or >0 (read locked), increment to add another read lock
        let cur_val = mode.get();
        if cur_val >= 0 {
            mode.set(cur_val + 1);
            true // success setting a read lock
        } else {
            false // read lock could not be added
        }
        // Mutex is unlocked by going out of scope
    }

    #[inline]
    pub fn write(&self) {
        // Repeat until the lock is obtained
        loop {
            let mut mode = self.mode.lock().unwrap();

            let cur_val = mode.get();
            // If value is 0 (unlocked), set it to -1 (write locked)
            if cur_val == 0 {
                mode.set(-1);
                return; // success setting the write lock
            }
            // Mutex is unlocked by going out of scope
        }
    }

    #[inline]
    pub fn try_write(&self) -> bool {
        // Get the mutex for exclusive access to 'mode'
        let mut mode = self.mode.lock().unwrap();

        let cur_val = mode.get();
        // If value is 0 (unlocked), set it to -1 (write locked)
        if cur_val == 0 {
            mode.set(-1);
            true // success setting the write lock
        } else {
            false
        }
        // Mutex is unlocked by going out of scope
    }

    #[inline]
    pub fn read_unlock(&self) {
        // Get the mutex for exclusive access to 'mode'
        let mut mode = self.mode.lock().unwrap();

        let cur_val = mode.get();
        // If value is >0 (read locked), decrement to remove one of the read locks
        if cur_val > 0 {
            mode.set(cur_val - 1);
        }
        // Mutex is unlocked by going out of scope
    }

    #[inline]
    pub fn write_unlock(&self) {
        // Get the mutex to access 'mode'.
        // Replace with 0 (= unlock), checking that the previous value was -1 (write locked)
        assert_eq!(self.mode.lock().unwrap().replace(0), -1);
        // Mutex is unlocked by going out of scope
    }
}

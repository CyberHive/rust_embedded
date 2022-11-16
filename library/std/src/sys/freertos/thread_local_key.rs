use crate::sync::atomic::{AtomicUsize, Ordering};
use freertos_rust::*;

//Not included in freertos rust bindings
extern "C" {
    fn vTaskSetThreadLocalStoragePointer(xTaskToSet: FreeRtosTaskHandle,  xIndex: usize, pvValue: *mut u8);
    fn pvTaskGetThreadLocalStoragePointer(xTaskToQuery: FreeRtosTaskHandle, xIndex: usize) -> *mut u8;
}

pub type Key = usize;

//TODO: Implement a key pool allowing keys to be added and removed
//For now, just use a counting index.
static mut key_index: AtomicUsize = AtomicUsize::new(0);
const MAX_KEYS: usize = 5; //This must correspond to configNUM_THREAD_LOCAL_STORAGE_POINTERS, but not yet enforced


#[inline]
pub unsafe fn create(_dtor: Option<unsafe extern "C" fn(*mut u8)>) -> Key {
    let ret = key_index.fetch_add(1, Ordering::Relaxed);
    assert!(ret < MAX_KEYS);
    ret
}

// Set the value associated with this TLS key
#[inline]
pub unsafe fn set(key: Key, value: *mut u8) {
    assert!(key < MAX_KEYS);
    vTaskSetThreadLocalStoragePointer(0 as FreeRtosTaskHandle, key, value );
}

// Get the value associated with this TLS key
#[inline]
pub unsafe fn get(key: Key) -> *mut u8 {
    assert!(key < MAX_KEYS);
    pvTaskGetThreadLocalStoragePointer(0 as FreeRtosTaskHandle, key )
}

#[inline]
pub unsafe fn destroy(_key: Key) {
    //Nothing here yet!
}

#[inline]
pub fn requires_synchronized_create() -> bool {
    false
}

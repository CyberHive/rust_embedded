use super::unsupported;
use crate::ffi::CStr;
use crate::io;
use crate::num::NonZeroUsize;
use crate::time::Duration;

use freertos_rust::*;

pub struct Thread {
    task: freertos_rust::Task,
}

unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

// This wrapper for the function pointer is necessary to make it Send. Box<dyn FnOnce()> is defined elsewhere (outside our
// control), and is not Send.
struct Fptr {
    fptr: Box<dyn FnOnce()>,
}
unsafe impl Send for Fptr {}

// Task wrapper function unwraps the task's function pointer and calls it. We can't do this directly in the call to
// freertos_rust::Task::new() because the non-Send function pointer then passes between threads.
fn launch_task(p: Fptr) {
    (p.fptr)();
}

pub const DEFAULT_MIN_STACK_SIZE: usize = 512;
pub const DEFAULT_MAX_STACK_SIZE: usize = 65535;

impl Thread {
    // unsafe: see thread::Builder::spawn_unchecked for safety requirements
    pub unsafe fn new(stack: usize, p: Box<dyn FnOnce()>) -> io::Result<Thread> {
        static mut num_rust_threads: u32 = 0;

        // FreeRTOS stack size is a u16. We should reject thread creation requests with larger stack than this can hold.
        assert!(
            stack <= DEFAULT_MAX_STACK_SIZE,
            "Stack size {} too large (maximum is {})",
            stack,
            DEFAULT_MAX_STACK_SIZE
        );
        // Also assert a sensible minimum stack size
        assert!(
            stack >= DEFAULT_MIN_STACK_SIZE,
            "Stack size {} too small (minimum is {})",
            stack,
            DEFAULT_MIN_STACK_SIZE
        );

        let stack_size = stack as u16;

        // std::Thread tries to start the thread then set its name. This is not possible in FreeRTOS.
        // So instead, FreeRTOS task names are just numbered RustThreads
        // Note that even though we don't assign the FreeRTOS task name, Rust still maintains thread names (used in panics etc).
        let thread_name = format!("RustThread{}", num_rust_threads);
        num_rust_threads = num_rust_threads + 1;
        let func_ptr_struct: Fptr = Fptr { fptr: p };

        // Create and start the FreeRTOS task
        let child_task = freertos_rust::Task::new()
            .name(thread_name.as_str())
            .stack_size(stack_size)
            .start(move || launch_task(func_ptr_struct))
            .unwrap();

        Ok(crate::sys::freertos::thread::Thread { task: child_task })
    }

    pub fn yield_now() {
        // It would be nice to call taskYIELD(), but this does not appear in Rust bindings
        // We can use the task delay function instead. A delay of 0 is equivalent to taskYIELD (it simply calls the scheduler).
        CurrentTask::delay(freertos_rust::Duration::ms(0));
    }

    pub fn set_name(name: &CStr) {
        // FreeRTOS does not expose a function to change the task's name after spawning (.start).
        // The builder can set the name between builder creation and .start() being called. That's not how std::thread works,
        // so this set_name function is essentially useless. Note that even though we don't assign the chosen thread name as
        // a FreeRTOS task name, Rust still maintains thread names (used in panics etc)
        // Rust still maintains thread names (used in panics etc).
    }

    pub fn sleep(dur: Duration) {
        // freertos_rust::Duration and std::time::Duration are different things. There appears to be no direct conversion, so
        // do it via millisecond values.
        // The duration's capacity differs (128 bits for std::time and 32 for freertos_rust).
        // Anything more than 2^32 milliseconds (49 days) which would overflow u32 is treated as infinite duration
        CurrentTask::delay(freertos_rust::Duration::ms(
            dur.as_millis().try_into().unwrap_or(freertos_rust::Duration::infinite().to_ms()),
        ));
    }

    pub fn join(self) {
        // FreeRTOS tasks are supposed to run forever; they are not supposed to complete (this is actually an error condition).
        // The only way to stop a FreeRTOS task is to delete it. Therefore, join() does not make sense, and cannot be supported.
        panic!("join() should not be called on a FreeRTOS task. This is unsupported");
    }
}

pub fn available_parallelism() -> io::Result<NonZeroUsize> {
    unsupported()
}

pub mod guard {
    pub type Guard = !;
    pub unsafe fn current() -> Option<Guard> {
        None
    }
    pub unsafe fn init() -> Option<Guard> {
        None
    }
}

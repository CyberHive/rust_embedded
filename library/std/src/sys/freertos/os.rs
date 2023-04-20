use super::unsupported;
use crate::error::Error as StdError;
use crate::ffi::{OsStr, OsString};
use crate::fmt;
use crate::io;
use crate::marker::PhantomData;
use crate::path::{self, PathBuf};
use core::ffi::c_int;

// FreeRTOS does not have a filesystem unless FreeRTOS-plus-FAT is used.
// For compatibility with 'vanilla' FreeRTOS, and since we don't rely on a filesystem, filesystem functions are stubbed and
// raise errors.

pub const EPERM: i32 = 1; // Operation not permitted
pub const ENOENT: i32 = 2; // No such file or directory
pub const ESRCH: i32 = 3; // No such process
pub const EINTR: i32 = 4; // Interrupted system call
pub const EIO: i32 = 5; // I/O error
pub const ENXIO: i32 = 6; // No such device or address
pub const E2BIG: i32 = 7; // Arg list too long
pub const ENOEXEC: i32 = 8; // Exec format error
pub const EBADF: i32 = 9; // Bad file number
pub const ECHILD: i32 = 10; // No child processes
pub const EAGAIN: i32 = 11; // Try again
pub const ENOMEM: i32 = 12; // Out of memory
pub const EACCES: i32 = 13; // Permission denied
pub const EFAULT: i32 = 14; // Bad address
pub const ENOTBLK: i32 = 15; // Block device required
pub const EBUSY: i32 = 16; // Device or resource busy
pub const EEXIST: i32 = 17; // File exists
pub const EXDEV: i32 = 18; // Cross-device link
pub const ENODEV: i32 = 19; // No such device
pub const ENOTDIR: i32 = 20; // Not a directory
pub const EISDIR: i32 = 21; // Is a directory
pub const EINVAL: i32 = 22; // Invalid argument
pub const ENFILE: i32 = 23; // File table overflow
pub const EMFILE: i32 = 24; // Too many open files
pub const ENOTTY: i32 = 25; // Not a typewriter
pub const ETXTBSY: i32 = 26; // Text file busy
pub const EFBIG: i32 = 27; // File too large
pub const ENOSPC: i32 = 28; // No space left on device
pub const ESPIPE: i32 = 29; // Illegal seek
pub const EROFS: i32 = 30; // Read-only file system
pub const EMLINK: i32 = 31; // Too many links
pub const EPIPE: i32 = 32; // Broken pipe
pub const EDOM: i32 = 33; // Math argument out of domain of func
pub const ERANGE: i32 = 34; // Math result not representable
pub const EDEADLK: i32 = 35; // Resource deadlock would occur
pub const ENAMETOOLONG: i32 = 36; // File name too long
pub const ENOLCK: i32 = 37; // No record locks available
pub const ENOSYS: i32 = 38; // Function not implemented
pub const ENOTEMPTY: i32 = 39; // Directory not empty
pub const ELOOP: i32 = 40; // Too many symbolic links encountered
pub const EWOULDBLOCK: i32 = EAGAIN; // Operation would block
pub const ENOMSG: i32 = 42; // No message of desired type
pub const EIDRM: i32 = 43; // Identifier removed
pub const ECHRNG: i32 = 44; // Channel number out of range
pub const EL2NSYNC: i32 = 45; // Level 2 not synchronized
pub const EL3HLT: i32 = 46; // Level 3 halted
pub const EL3RST: i32 = 47; // Level 3 reset
pub const ELNRNG: i32 = 48; // Link number out of range
pub const EUNATCH: i32 = 49; // Protocol driver not attached
pub const ENOCSI: i32 = 50; // No CSI structure available
pub const EL2HLT: i32 = 51; // Level 2 halted
pub const EBADE: i32 = 52; // Invalid exchange
pub const EBADR: i32 = 53; // Invalid request descriptor
pub const EXFULL: i32 = 54; // Exchange full
pub const ENOANO: i32 = 55; // No anode
pub const EBADRQC: i32 = 56; // Invalid request code
pub const EBADSLT: i32 = 57; // Invalid slot
pub const EDEADLOCK: i32 = EDEADLK;
pub const EBFONT: i32 = 59; // Bad font file format
pub const ENOSTR: i32 = 60; // Device not a stream
pub const ENODATA: i32 = 61; // No data available
pub const ETIME: i32 = 62; // Timer expired
pub const ENOSR: i32 = 63; // Out of streams resources
pub const ENONET: i32 = 64; // Machine is not on the network
pub const ENOPKG: i32 = 65; // Package not installed
pub const EREMOTE: i32 = 66; // Object is remote
pub const ENOLINK: i32 = 67; // Link has been severed
pub const EADV: i32 = 68; // Advertise error
pub const ESRMNT: i32 = 69; // Srmount error
pub const ECOMM: i32 = 70; // Communication error on send
pub const EPROTO: i32 = 71; // Protocol error
pub const EMULTIHOP: i32 = 72; // Multihop attempted
pub const EDOTDOT: i32 = 73; // RFS specific error
pub const EBADMSG: i32 = 74; // Not a data message
pub const EOVERFLOW: i32 = 75; // Value too large for defined data type
pub const ENOTUNIQ: i32 = 76; // Name not unique on network
pub const EBADFD: i32 = 77; // File descriptor in bad state
pub const EREMCHG: i32 = 78; // Remote address changed
pub const ELIBACC: i32 = 79; // Can not access a needed shared library
pub const ELIBBAD: i32 = 80; // Accessing a corrupted shared library
pub const ELIBSCN: i32 = 81; // .lib section in a.out corrupted
pub const ELIBMAX: i32 = 82; // Attempting to link in too many shared libraries
pub const ELIBEXEC: i32 = 83; // Cannot exec a shared library directly
pub const EILSEQ: i32 = 84; // Illegal byte sequence
pub const ERESTART: i32 = 85; // Interrupted system call should be restarted
pub const ESTRPIPE: i32 = 86; // Streams pipe error
pub const EUSERS: i32 = 87; // Too many users
pub const ENOTSOCK: i32 = 88; // Socket operation on non-socket
pub const EDESTADDRREQ: i32 = 89; // Destination address required
pub const EMSGSIZE: i32 = 90; // Message too long
pub const EPROTOTYPE: i32 = 91; // Protocol wrong type for socket
pub const ENOPROTOOPT: i32 = 92; // Protocol not available
pub const EPROTONOSUPPORT: i32 = 93; // Protocol not supported
pub const ESOCKTNOSUPPORT: i32 = 94; // Socket type not supported
pub const EOPNOTSUPP: i32 = 95; // Operation not supported on transport endpoint
pub const EPFNOSUPPORT: i32 = 96; // Protocol family not supported
pub const EAFNOSUPPORT: i32 = 97; // Address family not supported by protocol
pub const EADDRINUSE: i32 = 98; // Address already in use
pub const EADDRNOTAVAIL: i32 = 99; // Cannot assign requested address
pub const ENETDOWN: i32 = 100; // Network is down
pub const ENETUNREACH: i32 = 101; // Network is unreachable
pub const ENETRESET: i32 = 102; // Network dropped connection because of reset
pub const ECONNABORTED: i32 = 103; // Software caused connection abort
pub const ECONNRESET: i32 = 104; // Connection reset by peer
pub const ENOBUFS: i32 = 105; // No buffer space available
pub const EISCONN: i32 = 106; // Transport endpoint is already connected
pub const ENOTCONN: i32 = 107; // Transport endpoint is not connected
pub const ESHUTDOWN: i32 = 108; // Cannot send after transport endpoint shutdown
pub const ETOOMANYREFS: i32 = 109; // Too many references: cannot splice
pub const ETIMEDOUT: i32 = 110; // Connection timed out
pub const ECONNREFUSED: i32 = 111; // Connection refused
pub const EHOSTDOWN: i32 = 112; // Host is down
pub const EHOSTUNREACH: i32 = 113; // No route to host
pub const EALREADY: i32 = 114; // Operation already in progress
pub const EINPROGRESS: i32 = 115; // Operation now in progress
pub const ESTALE: i32 = 116; // Stale NFS file handle
pub const EUCLEAN: i32 = 117; // Structure needs cleaning
pub const ENOTNAM: i32 = 118; // Not a XENIX named type file
pub const ENAVAIL: i32 = 119; // No XENIX semaphores available
pub const EISNAM: i32 = 120; // Is a named type file
pub const EREMOTEIO: i32 = 121; // Remote I/O error
pub const EDQUOT: i32 = 122; // Quota exceeded
pub const ENOMEDIUM: i32 = 123; // No medium found
pub const EMEDIUMTYPE: i32 = 124; // Wrong medium type

const errno_text: [&str; 125] = [
    "No error",                                        // AOK
    "Operation not permitted",                         // EPERM
    "No such file or directory",                       // ENOENT
    "No such process",                                 // ESRCH
    "Interrupted system call",                         // EINTR
    "I/O error",                                       // EIO
    "No such device or address",                       // ENXIO
    "Arg list too long",                               // E2BIG
    "Exec format error",                               // ENOEXEC
    "Bad file number",                                 // EBADF
    "No child processes",                              // ECHILD
    "Try again",                                       // EAGAIN
    "Out of memory",                                   // ENOMEM
    "Permission denied",                               // EACCES
    "Bad address",                                     // EFAULT
    "Block device required",                           // ENOTBLK
    "Device or resource busy",                         // EBUSY
    "File exists",                                     // EEXIST
    "Cross-device link",                               // EXDEV
    "No such device",                                  // ENODEV
    "Not a directory",                                 // ENOTDIR
    "Is a directory",                                  // EISDIR
    "Invalid argument",                                // EINVAL
    "File table overflow",                             // ENFILE
    "Too many open files",                             // EMFILE
    "Not a typewriter",                                // ENOTTY
    "Text file busy",                                  // ETXTBSY
    "File too large",                                  // EFBIG
    "No space left on device",                         // ENOSPC
    "Illegal seek",                                    // ESPIPE
    "Read-only file system",                           // EROFS
    "Too many links",                                  // EMLINK
    "Broken pipe",                                     // EPIPE
    "Math argument out of domain of func",             // EDOM
    "Math result not representable",                   // ERANGE
    "Resource deadlock would occur",                   // EDEADLK
    "File name too long",                              // ENAMETOOLONG
    "No record locks available",                       // ENOLCK
    "Function not implemented",                        // ENOSYS
    "Directory not empty",                             // ENOTEMPTY
    "Too many symbolic links encountered",             // ELOOP
    "Operation would block",                           // EWOULDBLOCK
    "No message of desired type",                      // ENOMSG
    "Identifier removed",                              // EIDRM
    "Channel number out of range",                     // ECHRNG
    "Level 2 not synchronized",                        // EL2NSYNC
    "Level 3 halted",                                  // EL3HLT
    "Level 3 reset",                                   // EL3RST
    "Link number out of range",                        // ELNRNG
    "Protocol driver not attached",                    // EUNATCH
    "No CSI structure available",                      // ENOCSI
    "Level 2 halted",                                  // EL2HLT
    "Invalid exchange",                                // EBADE
    "Invalid request descriptor",                      // EBADR
    "Exchange full",                                   // EXFULL
    "No anode",                                        // ENOANO
    "Invalid request code",                            // EBADRQC
    "Invalid slot",                                    // EBADSLT
    "Deadlock",                                        // EDEADLOCK
    "Bad font file format",                            // EBFONT
    "Device not a stream",                             // ENOSTR
    "No data available",                               // ENODATA
    "Timer expired",                                   // ETIME
    "Out of streams resources",                        // ENOSR
    "Machine is not on the network",                   // ENONET
    "Package not installed",                           // ENOPKG
    "Object is remote",                                // EREMOTE
    "Link has been severed",                           // ENOLINK
    "Advertise error",                                 // EADV
    "Srmount error",                                   // ESRMNT
    "Communication error on send",                     // ECOMM
    "Protocol error",                                  // EPROTO
    "Multihop attempted",                              // EMULTIHOP
    "RFS specific error",                              // EDOTDOT
    "Not a data message",                              // EBADMSG
    "Value too large for defined data type",           // EOVERFLOW
    "Name not unique on network",                      // ENOTUNIQ
    "File descriptor in bad state",                    // EBADFD
    "Remote address changed",                          // EREMCHG
    "Can not access a needed shared library",          // ELIBACC
    "Accessing a corrupted shared library",            // ELIBBAD
    ".lib section in a.out corrupted",                 // ELIBSCN
    "Attempting to link in too many shared libraries", // ELIBMAX
    "Cannot exec a shared library directly",           // ELIBEXEC
    "Illegal byte sequence",                           // EILSEQ
    "Interrupted system call should be restarted",     // ERESTART
    "Streams pipe error",                              // ESTRPIPE
    "Too many users",                                  // EUSERS
    "Socket operation on non-socket",                  // ENOTSOCK
    "Destination address required",                    // EDESTADDRREQ
    "Message too long",                                // EMSGSIZE
    "Protocol wrong type for socket",                  // EPROTOTYPE
    "Protocol not available",                          // ENOPROTOOPT
    "Protocol not supported",                          // EPROTONOSUPPORT
    "Socket type not supported",                       // ESOCKTNOSUPPORT
    "Operation not supported on transport endpoint",   // EOPNOTSUPP
    "Protocol family not supported",                   // EPFNOSUPPORT
    "Address family not supported by protocol",        // EAFNOSUPPORT
    "Address already in use",                          // EADDRINUSE
    "Cannot assign requested address",                 // EADDRNOTAVAIL
    "Network is down",                                 // ENETDOWN
    "Network is unreachable",                          // ENETUNREACH
    "Network dropped connection because of reset",     // ENETRESET
    "Software caused connection abort",                // ECONNABORTED
    "Connection reset by peer",                        // ECONNRESET
    "No buffer space available",                       // ENOBUFS
    "Transport endpoint is already connected",         // EISCONN
    "Transport endpoint is not connected",             // ENOTCONN
    "Cannot send after transport endpoint shutdown",   // ESHUTDOWN
    "Too many references: cannot splice",              // ETOOMANYREFS
    "Connection timed out",                            // ETIMEDOUT
    "Connection refused",                              // ECONNREFUSED
    "Host is down",                                    // EHOSTDOWN
    "No route to host",                                // EHOSTUNREACH
    "Operation already in progress",                   // EALREADY
    "Operation now in progress",                       // EINPROGRESS
    "Stale NFS file handle",                           // ESTALE
    "Structure needs cleaning",                        // EUCLEAN
    "Not a XENIX named type file",                     // ENOTNAM
    "No XENIX semaphores available",                   // ENAVAIL
    "Is a named type file",                            // EISNAM
    "Remote I/O error",                                // EREMOTEIO
    "Quota exceeded",                                  // EDQUOT
    "No medium found",                                 // ENOMEDIUM
    "Wrong medium type",                               // EMEDIUMTYPE
];

pub fn errno() -> i32 {
    // Link with FreeRTOS' global errno (we don't need to expose this at the top level)
    extern "C" {
        #[no_mangle]
        static errno: c_int;
    }
    unsafe { errno }
}

pub fn error_string(errno: i32) -> String {
    if (errno < 0) || (errno >= errno_text.len()) {
        "Unknown error".to_string()
    } else {
        errno_text[errno as usize].to_string()
    }
}

pub fn getcwd() -> io::Result<PathBuf> {
    unsupported()
}

pub fn chdir(_: &path::Path) -> io::Result<()> {
    unsupported()
}

pub struct SplitPaths<'a>(!, PhantomData<&'a ()>);

pub fn split_paths(_unparsed: &OsStr) -> SplitPaths<'_> {
    panic!("not supported on FreeRTOS platform")
}

impl<'a> Iterator for SplitPaths<'a> {
    type Item = PathBuf;
    fn next(&mut self) -> Option<PathBuf> {
        self.0
    }
}

#[derive(Debug)]
pub struct JoinPathsError;

pub fn join_paths<I, T>(_paths: I) -> Result<OsString, JoinPathsError>
where
    I: Iterator<Item = T>,
    T: AsRef<OsStr>,
{
    Err(JoinPathsError)
}

impl fmt::Display for JoinPathsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        "not supported on FreeRTOS platform".fmt(f)
    }
}

impl StdError for JoinPathsError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "not supported on FreeRTOS platform"
    }
}

pub fn current_exe() -> io::Result<PathBuf> {
    unsupported()
}

pub struct Env(!);

impl Iterator for Env {
    type Item = (OsString, OsString);
    fn next(&mut self) -> Option<(OsString, OsString)> {
        self.0
    }
}

pub fn env() -> Env {
    panic!("not supported on FreeRTOS platform")
}

pub fn getenv(_: &OsStr) -> Option<OsString> {
    // getenv is actually called by panic! and probably other std functions. Although not supported, this needs to be benign.
    None
}

pub fn setenv(_: &OsStr, _: &OsStr) -> io::Result<()> {
    Err(io::const_io_error!(io::ErrorKind::Unsupported, "cannot set env vars on FreeRTOS platform"))
}

pub fn unsetenv(_: &OsStr) -> io::Result<()> {
    Err(io::const_io_error!(
        io::ErrorKind::Unsupported,
        "cannot unset env vars on FreeRTOS platform"
    ))
}

pub fn temp_dir() -> PathBuf {
    panic!("no filesystem on FreeRTOS platform")
}

pub fn home_dir() -> Option<PathBuf> {
    panic!("no filesystem on FreeRTOS platform");
    None
}

pub fn exit(_code: i32) -> ! {
    crate::intrinsics::abort()
}

pub fn getpid() -> u32 {
    panic!("no pids on FreeRTOS platform")
}

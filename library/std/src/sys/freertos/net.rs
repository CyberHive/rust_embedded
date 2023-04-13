use crate::cmp;
use crate::fmt;
use crate::io::Error;
use crate::io::ErrorKind::*;
use crate::io::{self, IoSlice, IoSliceMut, Read};
use crate::mem::size_of;
use crate::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use crate::sys::net::netc::*;
use crate::sys::os::errno;
use crate::sys::unsupported;
use crate::sys_common::net::sockaddr_to_addr;
use crate::time::Duration;
use core::ffi::{
    c_char, c_int, c_long, c_longlong, c_schar, c_short, c_uchar, c_uint, c_ulonglong, c_ushort,
    c_void,
};

// netc module interfaces to LwIP socket calls.
// This module is used by:
// - UdpSocket, TcpListener and TcpStream (in sys_common/net.rs)
// - Socket (below)
#[allow(nonstandard_style)]
pub mod netc {
    // Rust bindings for LwIP TCP/IP stack.
    include!("lwip-rs.rs");

    extern "C" {
        pub fn lwip_getaddrinfo(
            nodename: *const core::ffi::c_char,
            servname: *const core::ffi::c_char,
            hints: *const addrinfo,
            res: *mut *mut addrinfo,
        ) -> core::ffi::c_int;
    }
    extern "C" {
        pub fn lwip_freeaddrinfo(ai: *mut addrinfo);
    }

    use crate::mem::size_of;
    use crate::ptr;
    use crate::sys::net::RawSocket;
    use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

    // These constants need to be consistent with the definitions in LwIP's sockets.h
    // which unfortunately do not appear in the Rust bindings.
    // They have all been checked against these.
    pub const AF_INET6: i32 = 10; // Not supported in LwIP
    pub const AF_INET: i32 = 2;
    pub const IPPROTO_IPV6: i32 = 41; // Not supported in LwIP
    pub const IPV6_ADD_MEMBERSHIP: i32 = 12; // Not supported in LwIP
    pub const IPV6_DROP_MEMBERSHIP: i32 = 13; // Not supported in LwIP
    pub const IPV6_MULTICAST_LOOP: i32 = 19; // Not supported in LwIP
    pub const IPV6_V6ONLY: i32 = 27; // Not supported in LwIP
    pub const IP_TTL: i32 = 2;
    pub const IP_MULTICAST_TTL: i32 = 5;
    pub const IP_MULTICAST_LOOP: i32 = 7;
    pub const IP_ADD_MEMBERSHIP: i32 = 3;
    pub const IP_DROP_MEMBERSHIP: i32 = 4;
    pub const SHUT_RD: i32 = 0;
    pub const SHUT_RDWR: i32 = 2;
    pub const SHUT_WR: i32 = 1;
    pub const SOCK_DGRAM: i32 = 2;
    pub const SOCK_STREAM: i32 = 1;
    pub const SOL_SOCKET: i32 = 0xfff;
    pub const SO_BROADCAST: i32 = 32;
    pub const SO_ERROR: i32 = 0x1007;
    pub const SO_RCVTIMEO: i32 = 0x1006;
    pub const SO_REUSEADDR: i32 = 4;
    pub const SO_SNDTIMEO: i32 = 0x1005;
    pub const SO_LINGER: i32 = 0x80;
    pub const TCP_NODELAY: i32 = 1;
    pub const MSG_PEEK: c_int = 1;
    pub const FIONBIO: c_long = 0x8004667eu32 as c_long; // corrected: differs from Windows implementation

    // These were in 'unsupported'
    #[derive(Copy, Clone)]
    pub struct in6_addr {
        pub s6_addr: [u8; 16],
    }

    #[derive(Copy, Clone)]
    pub struct sockaddr_in6 {
        pub sin6_family: sa_family_t,
        pub sin6_port: u16,
        pub sin6_addr: in6_addr,
        pub sin6_flowinfo: u32,
        pub sin6_scope_id: u32,
    }

    //These borrowed from Windows SGX and other sources
    #[repr(C)]
    //#[derive(Debug, Copy, Clone)]
    pub struct addrinfo {
        pub ai_flags: c_int,
        pub ai_family: c_int,
        pub ai_socktype: c_int,
        pub ai_protocol: c_int,
        pub ai_addrlen: socklen_t,
        pub ai_addr: *mut sockaddr,
        pub ai_canonname: *mut c_char,
        pub ai_next: *mut addrinfo,
    }

    #[repr(C)]
    pub struct ip_mreq {
        pub imr_multiaddr: in_addr,
        pub imr_interface: in_addr,
    }

    #[repr(C)]
    pub struct ipv6_mreq {
        pub ipv6mr_multiaddr: in6_addr,
        pub ipv6mr_interface: c_uint,
    }

    pub fn setsockopt(
        sock: RawSocket,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: socklen_t,
    ) -> c_int {
        let retval = unsafe { lwip_setsockopt(sock.socket_handle, level, optname, optval, optlen) };
        match retval {
            0 => 0,
            _ => -1,
        }
    }

    pub fn getsockopt(
        sock: RawSocket,
        level: c_int,
        optname: c_int,
        optval: *mut c_void,
        optlen: *mut socklen_t,
    ) -> c_int {
        let retval = unsafe { lwip_getsockopt(sock.socket_handle, level, optname, optval, optlen) };
        match retval {
            0 => 0,
            _ => -1,
        }
    }

    pub fn bind(sock: RawSocket, name: *const sockaddr, namelen: socklen_t) -> c_int {
        let retval =
            unsafe { lwip_bind(sock.socket_handle, name as *const super::sockaddr, namelen) };
        match retval {
            0 => 0,
            _ => -1,
        }
    }

    pub fn connect(sock: RawSocket, name: *const sockaddr, namelen: socklen_t) -> c_int {
        let retval =
            unsafe { lwip_connect(sock.socket_handle, name as *const super::sockaddr, namelen) };
        match retval {
            0 => 0,
            _ => -1,
        }
    }

    pub fn listen(sock: RawSocket, backlog: c_int) -> c_int {
        let retval = unsafe { lwip_listen(sock.socket_handle, backlog) };
        match retval {
            0 => 0,
            _ => -1,
        }
    }

    pub fn getsockname(sock: RawSocket, name: *mut sockaddr, namelen: *mut socklen_t) -> c_int {
        unsafe {
            let retval = lwip_getsockname(sock.socket_handle, name, namelen);
            retval
        }
    }

    pub fn send(sock: RawSocket, mem: *const c_void, len: i32, flags: c_int) -> i32 {
        unsafe {
            let retval = lwip_send(
                sock.socket_handle,
                mem,
                len,
                0, // flags
            );

            retval
        }
    }

    pub fn sendto(
        sock: RawSocket,
        mem: *const c_void,
        len: i32,
        flags: c_int,
        to: *const sockaddr,
        tolen: socklen_t,
    ) -> i32 {
        match sock.socket_type {
            SOCK_DGRAM => unsafe {
                let retval = lwip_sendto(
                    sock.socket_handle,
                    mem,
                    len,
                    0, // flags
                    to as *const super::sockaddr,
                    tolen,
                );

                retval
            },
            // TCP sendto? Makes no sense.
            SOCK_STREAM => -1,
            // Catch-all
            _ => -1,
        }
    }

    pub fn recv(sock: RawSocket, mem: *mut c_void, len: i32, flags: c_int) -> i32 {
        let retval = unsafe { lwip_recv(sock.socket_handle, mem, len as size_t, flags) };

        retval
    }

    pub fn recvfrom(
        sock: RawSocket,
        mem: *mut c_void,
        len: i32,
        flags: c_int,
        from: *mut sockaddr,
        fromlen: *mut socklen_t,
    ) -> i32 {
        match sock.socket_type {
            SOCK_DGRAM => {
                let retval = unsafe {
                    lwip_recvfrom(
                        sock.socket_handle,
                        mem,
                        len as size_t,
                        flags,
                        from as *mut super::sockaddr,
                        fromlen,
                    )
                };

                retval
            }
            // TCP recvfrom? Makes no sense.
            SOCK_STREAM => -1,
            // Catch-all
            _ => -1,
        }
    }

    pub fn getpeername(sock: RawSocket, name: *mut sockaddr, namelen: *mut socklen_t) -> c_int {
        unsafe {
            let retval = lwip_getpeername(sock.socket_handle, name, namelen);
            retval
        }
    }

    pub fn getaddrinfo(
        nodename: *const c_char,
        servname: *const c_char,
        hints: *const addrinfo,
        res: *mut *mut addrinfo,
    ) -> c_int {
        let retval = unsafe { lwip_getaddrinfo(nodename, servname, hints, res) };
        retval
    }

    pub fn freeaddrinfo(ai: *mut addrinfo) {
        unsafe { lwip_freeaddrinfo(ai) };
    }
}
//###########################################################################################################################

//TODO: fill in the correct implementations
pub fn init() {
    println!("FreeRTOS net init");
    // Network init currently called by test harness. For now, can get away without putting it here.
    //###TODO:Add LwIP network init here!
}

pub type wrlen_t = i32;

#[doc(hidden)]
pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i8 i16 i32 i64 isize }

pub fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    if t.is_minus_one() {
        let err = io::Error::from_raw_os_error(errno());
        Err(err)
    } else {
        Ok(t)
    }
}

/// A variant of `cvt` for `getaddrinfo` which return 0 for a success.
pub fn cvt_gai(err: c_int) -> io::Result<()> {
    if err == 0 {
        Ok(())
    } else {
        //###TODO:fill in the error case
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet")) /* Should be Err(whatever last error was) */
    }
}

/// Just to provide the same interface as sys/unix/net.rs
pub fn cvt_r<T, F>(mut f: F) -> io::Result<T>
where
    T: IsMinusOne,
    F: FnMut() -> T,
{
    cvt(f())
}

// Socket implementation
#[stable(feature = "lwip_network", since = "1.64.0")]
#[derive(Clone)]
pub struct Socket {
    socket_handle: c_int,
    socket_type: c_int,
}

// This must match the timeval C definition
#[repr(C)]
struct Timeval {
    tv_sec: c_longlong,
    tv_usec: c_long,
}

impl Socket {
    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn new(addr: &SocketAddr, socket_type: c_int) -> io::Result<Socket> {
        let family = match *addr {
            SocketAddr::V4(..) => netc::AF_INET,
            SocketAddr::V6(..) => {
                return Err(io::const_io_error!(io::ErrorKind::Unsupported, "IPV6 not supported"));
            }
        };

        let socket_handle = unsafe { lwip_socket(family, socket_type, IPPROTO_IP) };

        match socket_handle {
            -1 => Err(io::const_io_error!(io::ErrorKind::Other, "Socket creation failed")),
            _ => {
                let socket = Socket { socket_handle: socket_handle, socket_type: socket_type };
                Ok(socket)
            }
        }
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn connect_timeout(&self, addr: &SocketAddr, timeout: Duration) -> io::Result<()> {
        todo!("missing Socket::connect_timeout implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn accept(&self, storage: *mut SocketAddr, len: *mut c_uint) -> io::Result<Socket> {
        let socket_handle =
            unsafe { lwip_accept(self.socket_handle, storage as *mut netc::sockaddr, len) };

        match socket_handle {
            -1 => Err(io::const_io_error!(io::ErrorKind::Other, "accept failed")),
            _ => {
                let socket = Socket { socket_handle: socket_handle, socket_type: self.socket_type };
                Ok(socket)
            }
        }
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn duplicate(&self) -> io::Result<Socket> {
        Ok(self.clone())
    }

    fn recv_with_flags(&self, buf: &mut [u8], flags: c_int) -> io::Result<usize> {
        let length = cmp::min(buf.len(), <wrlen_t>::MAX as usize) as wrlen_t;

        let result =
            unsafe { netc::recv(self.as_raw(), buf.as_mut_ptr() as *mut _, length, flags) };

        match result {
            -1 => Err(io::const_io_error!(io::ErrorKind::Other, "recv failed")),
            _ => Ok(result as usize),
        }
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, 0)
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        todo!("missing Socket::read_vectored implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn is_read_vectored(&self) -> bool {
        true
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, MSG_PEEK)
    }

    fn recv_from_with_flags(
        &self,
        buf: &mut [u8],
        flags: c_int,
    ) -> io::Result<(usize, SocketAddr)> {
        let length = cmp::min(buf.len(), <wrlen_t>::MAX as usize) as wrlen_t;
        let mut fromaddr = netc::sockaddr_storage {
            s2_len: size_of::<netc::sockaddr_storage>() as u8,
            ss_family: 0,
            s2_data1: [0; 2],
            s2_data2: [0; 3],
        };
        let mut addrlen: socklen_t = size_of::<netc::sockaddr_storage>() as socklen_t;

        let result = unsafe {
            netc::recvfrom(
                self.as_raw(),
                buf.as_mut_ptr() as *mut _,
                length,
                flags,
                &mut fromaddr as *mut _ as *mut _,
                &mut addrlen,
            )
        };

        match result {
            -1 => Err(io::const_io_error!(io::ErrorKind::Other, "recv_from failed")),
            _ => Ok((result as usize, sockaddr_to_addr(&fromaddr, fromaddr.s2_len as usize)?)),
        }
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_with_flags(buf, 0)
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_with_flags(buf, MSG_PEEK)
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        todo!("missing Socket::write_vectored implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn is_write_vectored(&self) -> bool {
        true
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn set_timeout(&self, dur: Option<Duration>, kind: c_int) -> io::Result<()> {
        // kind is SO_RCVTIMEO or SO_SNDTIMEO
        // We must convert the Duration to a Timeval structure (seconds and microseconds)
        let dur_sec = match dur {
            Some(dur) => dur.as_secs() as c_longlong,
            None => 0,
        };
        let dur_usec = match dur {
            Some(dur) => dur.subsec_micros() as c_int,
            None => 0,
        };
        if (dur_sec == 0) && (dur_usec == 0) {
            return Err(io::const_io_error!(
                io::ErrorKind::InvalidInput,
                "cannot set a 0 duration timeout",
            ));
        }
        let mut option = Timeval { tv_sec: dur_sec, tv_usec: dur_usec };

        let mut option_len = size_of::<Timeval>() as socklen_t;
        let retval = netc::setsockopt(
            self.as_raw(),
            netc::SOL_SOCKET as i32,
            kind,
            &mut option as *mut _ as *mut c_void,
            option_len,
        );
        match retval {
            0 => Ok(()),
            _ => Err(io::const_io_error!(io::ErrorKind::Other, "set_timeout failed")),
        }
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn timeout(&self, kind: c_int) -> io::Result<Option<Duration>> {
        // kind is SO_RCVTIMEO or SO_SNDTIMEO
        let mut option = Timeval { tv_sec: 0, tv_usec: 0 };
        let mut option_len = size_of::<Timeval>() as socklen_t;

        let retval = netc::getsockopt(
            self.as_raw(),
            netc::SOL_SOCKET as i32,
            kind,
            &mut option as *mut _ as *mut c_void,
            &mut option_len,
        );
        match retval {
            0 => {
                // Make a Duration struct, converting the usec fractional part to nsec.
                let timeout = Duration::new(option.tv_sec as u64, (option.tv_usec * 1000) as u32);
                if timeout.is_zero() {
                    return Ok(None);
                }
                Ok(Some(timeout))
            }
            _ => Err(io::const_io_error!(io::ErrorKind::Other, "timeout failed")),
        }
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        // Map Shutdown flavours to LWiP constants
        let how = match how {
            Shutdown::Write => netc::SHUT_WR,
            Shutdown::Read => netc::SHUT_RD,
            Shutdown::Both => netc::SHUT_RDWR,
        };
        let retval = unsafe { lwip_shutdown(self.socket_handle, how) };
        match retval {
            0 => Ok(()),
            _ => Err(io::const_io_error!(io::ErrorKind::Other, "shutdown failed")),
        }
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        // Generic lwip_ioctl function takes a mutable argument pointer.  In this case (FIONBIO), the argument is not written.
        // To keep Rust happy, we need to make a mutable copy to pass to the function
        let mut nonblocking_mut = nonblocking;

        let retval = unsafe {
            lwip_ioctl(self.socket_handle, FIONBIO, &mut nonblocking_mut as *mut _ as *mut c_void)
        };

        // lwip_ioctl(FIONBIO) has no failure conditions, but catch potential errors anyway
        match retval {
            0 => Ok(()),
            _ => Err(io::const_io_error!(io::ErrorKind::Other, "set_nonblocking failed")),
        }
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn set_linger(&self, linger: Option<Duration>) -> io::Result<()> {
        // Not supported by LwIP unless LWIP_SO_LINGER option is enabled.
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "SO_LINGER not supported"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn linger(&self) -> io::Result<Option<Duration>> {
        // Not supported by LwIP unless LWIP_SO_LINGER option is enabled.
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "SO_LINGER not supported"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        //Careful: lwip_setsockopt(,,TCP_NODELAY) will be reading an integer
        let mut option: c_int = nodelay as c_int;
        let mut option_len = size_of::<c_int>() as socklen_t;
        let retval = netc::setsockopt(
            self.as_raw(),
            netc::IPPROTO_TCP as i32,
            netc::TCP_NODELAY,
            &mut option as *mut _ as *mut c_void,
            option_len,
        );
        match retval {
            0 => Ok(()),
            _ => Err(io::const_io_error!(io::ErrorKind::Other, "set_nodelay failed")),
        }
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn nodelay(&self) -> io::Result<bool> {
        //Careful: lwip_getsockopt(,,TCP_NODELAY) will be writing an integer
        let mut option: c_int = 0;
        let mut option_len = size_of::<c_int>() as socklen_t;

        let retval = netc::getsockopt(
            self.as_raw(),
            netc::IPPROTO_TCP as i32,
            netc::TCP_NODELAY,
            &mut option as *mut _ as *mut c_void,
            &mut option_len,
        );
        match retval {
            0 => Ok(option != 0),
            _ => Err(io::const_io_error!(io::ErrorKind::Other, "nodelay failed")),
        }
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        let mut option: c_int = 0;
        let mut option_len = size_of::<c_int>() as socklen_t;
        let retval: c_int = netc::getsockopt(
            self.as_raw(),
            netc::SOL_SOCKET,
            netc::SO_ERROR,
            &mut option as *mut _ as *mut c_void,
            &mut option_len,
        );
        match retval {
            0 => Ok(Some(io::Error::from_raw_os_error(option as i32))),
            // LwIP's getsockopt doesn't return -1 for a SO_ERROR query, but catch that condition anyway
            _ => Err(io::const_io_error!(io::ErrorKind::Other, "take_error failed")),
        }
    }

    // This is used by sys_common code to abstract over Windows and Unix.
    // Probably means not needed here.
    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn as_raw(&self) -> RawSocket {
        let mut raw_socket =
            RawSocket { socket_handle: self.socket_handle, socket_type: self.socket_type }; //TODO: get rid of RawSocket completely
        raw_socket
    }
}

#[stable(feature = "lwip_network", since = "1.64.0")]
impl<'a> Read for &'a Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read(buf)
    }
}

//TODO:RawSocket is a Windows-ism that needs to be eliminated. We just have sockets.
#[stable(feature = "lwip_network", since = "1.64.0")]
#[derive(Debug, Copy, Clone)]
pub struct RawSocket {
    socket_handle: c_int,
    socket_type: c_int,
}

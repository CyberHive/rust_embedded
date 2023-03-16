use crate::cmp;
use crate::fmt;
use crate::io::Error;
use crate::io::ErrorKind::*;
use crate::io::{self, IoSlice, IoSliceMut, Read};
use crate::mem::size_of;
use crate::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use crate::sys::net::netc::*;
use crate::sys::unsupported;
use crate::sys_common::net::sockaddr_to_addr;
use crate::time::Duration;
use core::ffi::{
    c_char, c_int, c_long, c_longlong, c_schar, c_short, c_uchar, c_uint, c_ulonglong, c_ushort,
    c_void,
};

//TODO: empty structure with 'never' type
pub struct TcpStream(!);

impl TcpStream {
    pub fn connect(_: io::Result<&SocketAddr>) -> io::Result<TcpStream> {
        todo!("missing TcpStream::connect implementation");
        unsupported()
    }

    pub fn connect_timeout(_: &SocketAddr, _: Duration) -> io::Result<TcpStream> {
        todo!("missing TcpStream::connect_timeout implementation");
        unsupported()
    }

    pub fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        todo!("missing TcpStream::set_read_timeout implementation");
        self.0
    }

    pub fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        todo!("missing TcpStream::set_write_timeout implementation");
        self.0
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        todo!("missing TcpStream::read_timeout implementation");
        self.0
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        todo!("missing TcpStream::write_timeout implementation");
        self.0
    }

    pub fn peek(&self, _: &mut [u8]) -> io::Result<usize> {
        todo!("missing TcpStream::peek implementation");
        self.0
    }

    pub fn read(&self, _: &mut [u8]) -> io::Result<usize> {
        todo!("missing TcpStream::read implementation");
        unsupported()
    }

    pub fn read_vectored(&self, _: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        todo!("missing TcpStream::read_vectored implementation");
        self.0
    }

    pub fn is_read_vectored(&self) -> bool {
        todo!("missing TcpStream::is_read_vectored implementation");
        self.0
    }

    pub fn write(&self, _: &[u8]) -> io::Result<usize> {
        todo!("missing TcpStream::write implementation");
        unsupported()
    }

    pub fn write_vectored(&self, _: &[IoSlice<'_>]) -> io::Result<usize> {
        todo!("missing TcpStream::write_vectored implementation");
        self.0
    }

    pub fn is_write_vectored(&self) -> bool {
        todo!("missing TcpStream::is_write_vectored implementation");
        self.0
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        todo!("missing TcpStream::peer_addr implementation");
        self.0
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        todo!("missing TcpStream::socket_addr implementation");
        self.0
    }

    pub fn shutdown(&self, _: Shutdown) -> io::Result<()> {
        todo!("missing TcpStream::shutdown implementation");
        self.0
    }

    pub fn duplicate(&self) -> io::Result<TcpStream> {
        todo!("missing TcpStream::duplicate implementation");
        self.0
    }

    pub fn set_linger(&self, _: Option<Duration>) -> io::Result<()> {
        todo!("missing TcpStream::set_linger implementation");
        self.0
    }

    pub fn linger(&self) -> io::Result<Option<Duration>> {
        todo!("missing TcpStream::linger implementation");
        self.0
    }

    pub fn set_nodelay(&self, _: bool) -> io::Result<()> {
        todo!("missing TcpStream::set_nodelay implementation");
        self.0
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        todo!("missing TcpStream::nodelay implementation");
        self.0
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        todo!("missing TcpStream::set_ttl implementation");
        self.0
    }

    pub fn ttl(&self) -> io::Result<u32> {
        todo!("missing TcpStream::ttl implementation");
        self.0
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        todo!("missing TcpStream::take_error implementation");
        self.0
    }

    pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        todo!("missing TcpStream::set_nonblocking implementation");
        self.0
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("missing fmt::Debug for TcpStream implementation");
        self.0
    }
}

//TODO: empty structure with 'never' type
pub struct TcpListener(!);

impl TcpListener {
    pub fn bind(_: io::Result<&SocketAddr>) -> io::Result<TcpListener> {
        todo!("missing TcpListener::bind implementation");
        unsupported()
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        todo!("missing TcpListener::socket_addr implementation");
        self.0
    }

    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        todo!("missing TcpListener::accept implementation");
        unsupported()
    }

    pub fn duplicate(&self) -> io::Result<TcpListener> {
        todo!("missing TcpListener::duplicate implementation");
        self.0
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        todo!("missing TcpListener::set_ttl implementation");
        self.0
    }

    pub fn ttl(&self) -> io::Result<u32> {
        todo!("missing TcpListener::ttl implementation");
        self.0
    }

    pub fn set_only_v6(&self, _: bool) -> io::Result<()> {
        todo!("missing TcpListener::set_only_v6 implementation");
        self.0
    }

    pub fn only_v6(&self) -> io::Result<bool> {
        todo!("missing TcpListener::only_v6 implementation");
        self.0
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        todo!("missing TcpListener::take_error implementation");
        self.0
    }

    pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        todo!("missing TcpListener::set_nonblocking implementation");
        self.0
    }
}

impl fmt::Debug for TcpListener {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("missing fmt::Debug for TcpListener implementation");
        self.0
    }
}

//TODO: empty structure with 'never' type
pub struct UdpSocket(!);

impl UdpSocket {
    pub fn bind(_: io::Result<&SocketAddr>) -> io::Result<UdpSocket> {
        todo!("missing UdpSocket::bind implementation");
        unsupported()
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        todo!("missing UdpSocket::peer_addr implementation");
        self.0
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        todo!("missing UdpSocket::socket_addr implementation");
        self.0
    }

    pub fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        todo!("missing UdpSocket::recv_from implementation");
        unsupported()
    }

    pub fn peek_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        todo!("missing UdpSocket::peek_from implementation");
        unsupported()
    }

    pub fn send_to(&self, _: &[u8], _: &SocketAddr) -> io::Result<usize> {
        todo!("missing UdpSocket::send_to implementation");
        unsupported()
    }

    pub fn duplicate(&self) -> io::Result<UdpSocket> {
        todo!("missing UdpSocket::duplicate implementation");
        self.0
    }

    pub fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        todo!("missing UdpSocket::set_read_timeout implementation");
        self.0
    }

    pub fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        todo!("missing UdpSocket::set_write_timeout implementation");
        self.0
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        todo!("missing UdpSocket::read_timeout implementation");
        self.0
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        todo!("missing UdpSocket::write_timeout implementation");
        self.0
    }

    pub fn set_broadcast(&self, _: bool) -> io::Result<()> {
        todo!("missing UdpSocket::set_broadcast implementation");
        self.0
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        todo!("missing UdpSocket::broadcast implementation");
        unsupported()
    }

    pub fn set_multicast_loop_v4(&self, _: bool) -> io::Result<()> {
        todo!("missing UdpSocket::set_multicast_loop_v4 implementation");
        self.0
    }

    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        todo!("missing UdpSocket::multicast_loop_v4 implementation");
        self.0
    }

    pub fn set_multicast_ttl_v4(&self, _: u32) -> io::Result<()> {
        todo!("missing UdpSocket::set_multicast_ttl_v4 implementation");
        self.0
    }

    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        todo!("missing UdpSocket::multicast_ttl_v4 implementation");
        self.0
    }

    pub fn set_multicast_loop_v6(&self, _: bool) -> io::Result<()> {
        todo!("missing UdpSocket::set_multicast_loop_v6 implementation");
        self.0
    }

    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        todo!("missing UdpSocket::multicast_loop_v6 implementation");
        self.0
    }

    pub fn join_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> io::Result<()> {
        todo!("missing UdpSocket::join_multicast_v4 implementation");
        self.0
    }

    pub fn join_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
        todo!("missing UdpSocket::join_multicast_v6 implementation");
        self.0
    }

    pub fn leave_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> io::Result<()> {
        todo!("missing UdpSocket::leave_multicast_v4 implementation");
        self.0
    }

    pub fn leave_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
        todo!("missing UdpSocket::leave_multicast_v6 implementation");
        self.0
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        todo!("missing UdpSocket::set_ttl implementation");
        self.0
    }

    pub fn ttl(&self) -> io::Result<u32> {
        todo!("missing UdpSocket::ttl implementation");
        self.0
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        todo!("missing UdpSocket::take_error implementation");
        self.0
    }

    pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        todo!("missing UdpSocket::set_nonblocking implementation");
        self.0
    }

    pub fn recv(&self, _: &mut [u8]) -> io::Result<usize> {
        todo!("missing UdpSocket::recv implementation");
        unsupported()
    }

    pub fn peek(&self, _: &mut [u8]) -> io::Result<usize> {
        todo!("missing UdpSocket::peek implementation");
        unsupported()
    }

    pub fn send(&self, _: &[u8]) -> io::Result<usize> {
        todo!("missing UdpSocket::send implementation");
        unsupported()
    }

    pub fn connect(&self, _: io::Result<&SocketAddr>) -> io::Result<()> {
        todo!("missing UdpSocket::connect implementation");
        unsupported()
    }
}

impl fmt::Debug for UdpSocket {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("missing fmt::Debug for UdpSocket implementation");
        self.0
    }
}

//TODO: empty structure with 'never' type
pub struct LookupHost(!);

impl LookupHost {
    pub fn port(&self) -> u16 {
        todo!("missing LookupHost::port implementation");
        self.0
    }
}

impl Iterator for LookupHost {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> {
        todo!("missing LookupHost::next implementation");
        self.0
    }
}

impl TryFrom<&str> for LookupHost {
    type Error = io::Error;

    fn try_from(_v: &str) -> io::Result<LookupHost> {
        todo!("missing LookupHost::try_from (_v: &str) implementation");
        unsupported()
    }
}

impl<'a> TryFrom<(&'a str, u16)> for LookupHost {
    type Error = io::Error;

    fn try_from(_v: (&'a str, u16)) -> io::Result<LookupHost> {
        todo!("missing LookupHost::try_from(&'a str, u16) implementation");
        unsupported()
    }
}

//###########################################################################################################################
#[allow(nonstandard_style)]
pub mod netc {
    // Rust bindings for LwIP TCP/IP stack.
    include!("lwip-rs.rs");

    use crate::mem::size_of;
    use crate::ptr;
    use crate::sys::net::RawSocket;
    use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
    // TODO: These constants borrowed from Windows implementation. They need to correlate to equivalents in LwIP - definitely need changes
    // TODO: Caller in sys_common explicitly uses constants in netc scope. Check for duplicates which are also
    // defined in lwip Rust bindings.
    pub const AF_INET6: i32 = 10;
    pub const AF_INET: i32 = 2;
    pub const IPPROTO_IPV6: i32 = 41; //Not supported in LwIP
    pub const IPV6_ADD_MEMBERSHIP: i32 = 12;
    pub const IPV6_DROP_MEMBERSHIP: i32 = 13;
    pub const IPV6_MULTICAST_LOOP: i32 = 19;
    pub const IPV6_V6ONLY: i32 = 27;
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
    pub const SOL_SOCKET: i32 = 4095;
    pub const SO_BROADCAST: i32 = 32;
    pub const SO_ERROR: i32 = 4103;
    pub const SO_RCVTIMEO: i32 = 4102;
    pub const SO_REUSEADDR: i32 = 4;
    pub const SO_SNDTIMEO: i32 = 4101;
    pub const SO_LINGER: i32 = 128;
    pub const TCP_NODELAY: i32 = 1;
    pub const MSG_PEEK: c_int = 1;
    pub const FIONBIO: c_long = 0x8008667eu32 as c_long;
    pub const EAI_NONAME: i32 = -2200;
    pub const EAI_SERVICE: i32 = -2201;
    pub const EAI_FAIL: i32 = -2202;
    pub const EAI_MEMORY: i32 = -2203;
    pub const EAI_FAMILY: i32 = -2204;

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

    //TODO: Oddly, other implementations don't seem to have these. Need to work out where they are hidden!
    pub fn setsockopt(
        sock: RawSocket,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: socklen_t,
    ) -> c_int {
        todo!("missing netc::setsockopt implementation");
        0
    }

    pub fn getsockopt(
        sock: RawSocket,
        level: c_int,
        optname: c_int,
        optval: *mut c_void,
        optlen: *mut socklen_t,
    ) -> c_int {
        todo!("missing netc::getsockopt implementation");
        0
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
        todo!("missing netc::listen implementation");
        0
    }

    pub fn getsockname(sock: RawSocket, name: *mut sockaddr, namelen: *mut socklen_t) -> c_int {
        todo!("missing netc::getsockname implementation");
        0
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
        todo!("missing netc::getpeername implementation");
        0
    }

    pub fn getaddrinfo(
        nodename: *const c_char,
        servname: *const c_char,
        hints: *const addrinfo,
        res: *mut *mut addrinfo,
    ) -> c_int {
        todo!("missing netc::getaddrinfo implementation");
        0
    }

    pub fn freeaddrinfo(ai: *mut addrinfo) {
        todo!("missing netc::freeaddrinfo implementation");
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

pub fn cvt<T>(t: T) -> io::Result<T> {
    Ok(t)
    //###TODO:Check the last error!
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
    //T: IsMinusOne,
    F: FnMut() -> T,
{
    cvt(f())
}

//###########################################################################################################################
//###Socket 'empty shell' functions adapted from Windows implementation
#[stable(feature = "lwip_network", since = "1.64.0")]
pub struct Socket {
    socket_handle: c_int,
    socket_type: c_int,
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
        todo!("missing Socket::accept implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn duplicate(&self) -> io::Result<Socket> {
        //Ok(Self(self.0.try_clone()?))
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
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
        todo!("missing Socket::set_timeout implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn timeout(&self, kind: c_int) -> io::Result<Option<Duration>> {
        todo!("missing Socket::timeout implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        todo!("missing Socket::shutdown implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        todo!("missing Socket::set_nonblocking implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn set_linger(&self, linger: Option<Duration>) -> io::Result<()> {
        todo!("missing Socket::set_linger implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn linger(&self) -> io::Result<Option<Duration>> {
        todo!("missing Socket::linger implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        todo!("missing Socket::set_nodelay implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn nodelay(&self) -> io::Result<bool> {
        todo!("missing Socket::nodelay implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    #[stable(feature = "lwip_network", since = "1.64.0")]
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        todo!("missing Socket::take_error implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
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

/*
impl AsRawSocket for Socket {
    fn as_raw_socket(&self) -> RawSocket {
        self.0.as_raw_socket()
    }
}

impl IntoRawSocket for Socket {
    fn into_raw_socket(self) -> RawSocket {
        self.0.into_raw_socket()
    }
}

impl FromRawSocket for Socket {
    unsafe fn from_raw_socket(raw_socket: RawSocket) -> Self {
        Self(FromRawSocket::from_raw_socket(raw_socket))
    }
}
*/

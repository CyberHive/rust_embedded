use crate::fmt;
use crate::io::Error;
use crate::io::ErrorKind::*;
use crate::io::{self, IoSlice, IoSliceMut, Read};
use crate::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use crate::sys::net::netc::*;
use crate::sys::unsupported;
use crate::time::Duration;
use core::ffi::{c_int, c_long, c_uint};

//TODO: empty structure with 'never' type
pub struct TcpStream(!);

impl TcpStream {
    pub fn connect(_: io::Result<&SocketAddr>) -> io::Result<TcpStream> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn connect_timeout(_: &SocketAddr, _: Duration) -> io::Result<TcpStream> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        todo!("missing implementation");
        self.0
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        todo!("missing implementation");
        self.0
    }

    pub fn peek(&self, _: &mut [u8]) -> io::Result<usize> {
        todo!("missing implementation");
        self.0
    }

    pub fn read(&self, _: &mut [u8]) -> io::Result<usize> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn read_vectored(&self, _: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        todo!("missing implementation");
        self.0
    }

    pub fn is_read_vectored(&self) -> bool {
        todo!("missing implementation");
        self.0
    }

    pub fn write(&self, _: &[u8]) -> io::Result<usize> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn write_vectored(&self, _: &[IoSlice<'_>]) -> io::Result<usize> {
        todo!("missing implementation");
        self.0
    }

    pub fn is_write_vectored(&self) -> bool {
        todo!("missing implementation");
        self.0
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        todo!("missing implementation");
        self.0
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        todo!("missing implementation");
        self.0
    }

    pub fn shutdown(&self, _: Shutdown) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn duplicate(&self) -> io::Result<TcpStream> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_linger(&self, _: Option<Duration>) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn linger(&self) -> io::Result<Option<Duration>> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_nodelay(&self, _: bool) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn ttl(&self) -> io::Result<u32> {
        todo!("missing implementation");
        self.0
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("missing implementation");
        self.0
    }
}

//TODO: empty structure with 'never' type
pub struct TcpListener(!);

impl TcpListener {
    pub fn bind(_: io::Result<&SocketAddr>) -> io::Result<TcpListener> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        todo!("missing implementation");
        self.0
    }

    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn duplicate(&self) -> io::Result<TcpListener> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn ttl(&self) -> io::Result<u32> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_only_v6(&self, _: bool) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn only_v6(&self) -> io::Result<bool> {
        todo!("missing implementation");
        self.0
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }
}

impl fmt::Debug for TcpListener {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("missing implementation");
        self.0
    }
}

//TODO: empty structure with 'never' type
pub struct UdpSocket(!);

impl UdpSocket {
    pub fn bind(_: io::Result<&SocketAddr>) -> io::Result<UdpSocket> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        todo!("missing implementation");
        self.0
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        todo!("missing implementation");
        self.0
    }

    pub fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn peek_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn send_to(&self, _: &[u8], _: &SocketAddr) -> io::Result<usize> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn duplicate(&self) -> io::Result<UdpSocket> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        todo!("missing implementation");
        self.0
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_broadcast(&self, _: bool) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn set_multicast_loop_v4(&self, _: bool) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_multicast_ttl_v4(&self, _: u32) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_multicast_loop_v6(&self, _: bool) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        todo!("missing implementation");
        self.0
    }

    pub fn join_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn join_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn leave_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn leave_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn ttl(&self) -> io::Result<u32> {
        todo!("missing implementation");
        self.0
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        todo!("missing implementation");
        self.0
    }

    pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        todo!("missing implementation");
        self.0
    }

    pub fn recv(&self, _: &mut [u8]) -> io::Result<usize> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn peek(&self, _: &mut [u8]) -> io::Result<usize> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn send(&self, _: &[u8]) -> io::Result<usize> {
        todo!("missing implementation");
        unsupported()
    }

    pub fn connect(&self, _: io::Result<&SocketAddr>) -> io::Result<()> {
        todo!("missing implementation");
        unsupported()
    }
}

impl fmt::Debug for UdpSocket {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("missing implementation");
        self.0
    }
}

//TODO: empty structure with 'never' type
pub struct LookupHost(!);

impl LookupHost {
    pub fn port(&self) -> u16 {
        todo!("missing implementation");
        self.0
    }
}

impl Iterator for LookupHost {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> {
        todo!("missing implementation");
        self.0
    }
}

impl TryFrom<&str> for LookupHost {
    type Error = io::Error;

    fn try_from(_v: &str) -> io::Result<LookupHost> {
        todo!("missing implementation");
        unsupported()
    }
}

impl<'a> TryFrom<(&'a str, u16)> for LookupHost {
    type Error = io::Error;

    fn try_from(_v: (&'a str, u16)) -> io::Result<LookupHost> {
        todo!("missing implementation");
        unsupported()
    }
}

#[allow(nonstandard_style)]
pub mod netc {
    //###########################################################################################################################
    // TODO: These constants borrowed from Windows implementation. They need to correlate to equivalents in LwIP.
    pub const AF_INET6: i32 = 10;
    pub const AF_INET: i32 = 2;
    pub const IPPROTO_IP: i32 = 0;
    pub const IPPROTO_IPV6: i32 = 41;
    pub const IPPROTO_TCP: i32 = 6;
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
    pub const MSG_PEEK: core::ffi::c_int = 1;
    pub const FIONBIO: core::ffi::c_long = 0x8008667eu32 as core::ffi::c_long;
    pub const EAI_NONAME: i32 = -2200;
    pub const EAI_SERVICE: i32 = -2201;
    pub const EAI_FAIL: i32 = -2202;
    pub const EAI_MEMORY: i32 = -2203;
    pub const EAI_FAMILY: i32 = -2204;
    //###########################################################################################################################

    pub type sa_family_t = u8;
    pub type socklen_t = u32;
    pub type in_addr_t = u32;
    pub type in_port_t = u16;

    //###########################################################################################################################
    // These were in 'unsupported'
    #[derive(Copy, Clone)]
    pub struct in_addr {
        pub s_addr: u32,
    }

    #[derive(Copy, Clone)]
    pub struct sockaddr_in {
        pub sin_family: sa_family_t,
        pub sin_port: u16,
        pub sin_addr: in_addr,
    }

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

    //###########################################################################################################################
    //These borrowed from Windows SGX and other sources
    #[repr(C)]
    //#[derive(Debug, Copy, Clone)]
    pub struct addrinfo {
        pub ai_flags: core::ffi::c_int,
        pub ai_family: core::ffi::c_int,
        pub ai_socktype: core::ffi::c_int,
        pub ai_protocol: core::ffi::c_int,
        pub ai_addrlen: socklen_t,
        pub ai_addr: *mut sockaddr,
        pub ai_canonname: *mut core::ffi::c_char,
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
        pub ipv6mr_interface: core::ffi::c_uint,
    }

    #[repr(C)]
    pub struct sockaddr_storage {
        pub s2_len: u8,
        pub ss_family: sa_family_t,
        pub s2_data1: [core::ffi::c_char; 2usize],
        pub s2_data2: [u32; 3usize],
    }

    //###########################################################################################################################

    //TODO: fill this in
    #[derive(Copy, Clone)]
    pub struct sockaddr {}

    //###########################################################################################################################
    //TODO: Oddly, other implementations don't seem to have these. Need to work out where they are hidden!
    pub fn setsockopt() {}

    pub fn getsockopt() {
        todo!("missing implementation");
    }

    pub fn bind() {
        todo!("missing implementation");
    }

    pub fn connect() {
        todo!("missing implementation");
    }

    pub fn listen() {
        todo!("missing implementation");
    }

    pub fn getsockname() {
        todo!("missing implementation");
    }

    pub fn send() {
        todo!("missing implementation");
    }

    pub fn sendto() {
        todo!("missing implementation");
    }

    pub fn recv() {
        todo!("missing implementation");
    }

    pub fn recvfrom() {
        todo!("missing implementation");
    }

    pub fn getpeername() {
        todo!("missing implementation");
    }

    pub fn getaddrinfo() {
        todo!("missing implementation");
    }

    pub fn freeaddrinfo() {
        todo!("missing implementation");
    }

    //###########################################################################################################################
}

//TODO: fill in the correct implementations
pub fn init() {
    println!("FreeRTOS net init");
    //###TODO:Add LwIP network init!
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
pub struct Socket {
    socket_index: u32,
}

impl Socket {
    pub fn new(addr: &SocketAddr, socket_type: c_int) -> io::Result<Socket> {
        todo!("missing implementation");
        let family = match *addr {
            SocketAddr::V4(..) => netc::AF_INET,
            SocketAddr::V6(..) => netc::AF_INET6,
        };
        let mut socket = Socket { socket_index: 1 }; //TODO: initialise socket state variables
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn connect_timeout(&self, addr: &SocketAddr, timeout: Duration) -> io::Result<()> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn accept(&self, storage: *mut netc::sockaddr, len: *mut c_int) -> io::Result<Socket> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn duplicate(&self) -> io::Result<Socket> {
        //Ok(Self(self.0.try_clone()?))
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    fn recv_with_flags(&self, buf: &mut [u8], flags: c_int) -> io::Result<usize> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, 0)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn is_read_vectored(&self) -> bool {
        true
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, MSG_PEEK)
    }

    fn recv_from_with_flags(
        &self,
        buf: &mut [u8],
        flags: c_int,
    ) -> io::Result<(usize, SocketAddr)> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_with_flags(buf, 0)
    }

    pub fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_with_flags(buf, MSG_PEEK)
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn is_write_vectored(&self) -> bool {
        true
    }

    pub fn set_timeout(&self, dur: Option<Duration>, kind: c_int) -> io::Result<()> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn timeout(&self, kind: c_int) -> io::Result<Option<Duration>> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn set_linger(&self, linger: Option<Duration>) -> io::Result<()> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn linger(&self) -> io::Result<Option<Duration>> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        todo!("missing implementation");
        Err(io::const_io_error!(io::ErrorKind::Unsupported, "Not implemented for FreeRTOS yet"))
    }

    // This is used by sys_common code to abstract over Windows and Unix.
    // Probably means not needed here.
    pub fn as_raw(&self) -> RawSocket {
        let mut raw_socket = RawSocket { socket_index: 1 }; //TODO: get rid of RawSocket completely
        raw_socket
    }
}

#[unstable(reason = "not public", issue = "none", feature = "fd_read")]
impl<'a> Read for &'a Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read(buf)
    }
}

//TODO:RawSocket is a Windows-ism that needs to be eliminated. We just have sockets.
pub struct RawSocket {
    socket_index: u32,
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

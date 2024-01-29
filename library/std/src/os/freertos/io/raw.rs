//! freertos-specific extensions to general I/O primitives.

#![stable(feature = "lwip_network", since = "1.64.0")]

use crate::net;
#[cfg(doc)]
use crate::os::freertos::io::{AsHandle, AsSocket};
use crate::sys::net::Socket;
use crate::sys_common::{self, AsInner, FromInner, IntoInner};
use core::ffi::c_int;

/// Raw SOCKETs.
// RawSocket holds the same state variables as Socket. It is useful as a clone of Socket, which does not call lwip_close
// when dropped.
#[stable(feature = "lwip_network", since = "1.64.0")]
pub type RawSocket = c_int;

/// Extracts raw sockets.
#[stable(feature = "lwip_network", since = "1.64.0")]
pub trait AsRawSocket {
    /// Extracts the raw socket.
    ///
    /// This function is typically used to **borrow** an owned socket.
    /// When used in this way, this method does **not** pass ownership of the
    /// raw socket to the caller, and the socket is only guaranteed
    /// to be valid while the original object has not yet been destroyed.
    #[stable(feature = "lwip_network", since = "1.64.0")]
    fn as_raw_socket(&self) -> RawSocket;
}

/// Creates I/O objects from raw sockets.
#[stable(feature = "lwip_network", since = "1.64.0")]
pub trait FromRawSocket {
    /// Constructs a new I/O object from the specified raw socket.
    ///
    /// This function is typically used to **consume ownership** of the socket
    /// given, passing responsibility for closing the socket to the returned
    /// object. When used in this way, the returned object
    /// will take responsibility for closing it when the object goes out of
    /// scope.
    ///
    /// However, consuming ownership is not strictly required. Use a
    /// `From<OwnedSocket>::from` implementation for an API which strictly
    /// consumes ownership.
    ///
    /// # Safety
    ///
    /// The `socket` passed in must:
    ///   - be a valid an open socket,
    ///   - be a socket that may be freed via lwip_close (achieved by assimilation
    ///     into a socket type that calls lwip_close on drop())
    #[stable(feature = "lwip_network", since = "1.64.0")]
    unsafe fn from_raw_socket(sock: RawSocket) -> Self;
}

/// A trait to express the ability to consume an object and acquire ownership of
/// its raw `SOCKET`.
#[stable(feature = "lwip_network", since = "1.64.0")]
pub trait IntoRawSocket {
    /// Consumes this object, returning the raw underlying socket.
    ///
    /// This function is typically used to **transfer ownership** of the underlying
    /// socket to the caller. When used in this way, callers are then the unique
    /// owners of the socket and must close it once it's no longer needed.
    ///
    /// However, transferring ownership is not strictly required. Use a
    /// `Into<Socket>::into` implementation for an API which strictly
    /// transfers ownership.
    #[stable(feature = "lwip_network", since = "1.64.0")]
    fn into_raw_socket(self) -> RawSocket;
}

#[stable(feature = "lwip_network", since = "1.64.0")]
impl AsRawSocket for net::TcpStream {
    #[inline]
    fn as_raw_socket(&self) -> RawSocket {
        self.as_inner().socket().as_raw_socket()
    }
}
#[stable(feature = "lwip_network", since = "1.64.0")]
impl AsRawSocket for net::TcpListener {
    #[inline]
    fn as_raw_socket(&self) -> RawSocket {
        self.as_inner().socket().as_raw_socket()
    }
}
#[stable(feature = "lwip_network", since = "1.64.0")]
impl AsRawSocket for net::UdpSocket {
    #[inline]
    fn as_raw_socket(&self) -> RawSocket {
        self.as_inner().socket().as_raw_socket()
    }
}

#[stable(feature = "lwip_network", since = "1.64.0")]
impl FromRawSocket for net::TcpStream {
    #[inline]
    unsafe fn from_raw_socket(raw_socket: RawSocket) -> net::TcpStream {
        let sock = Socket::from_raw_socket(raw_socket);
        net::TcpStream::from_inner(sys_common::net::TcpStream::from_inner(sock))
    }
}
#[stable(feature = "lwip_network", since = "1.64.0")]
impl FromRawSocket for net::TcpListener {
    #[inline]
    unsafe fn from_raw_socket(raw_socket: RawSocket) -> net::TcpListener {
        let sock = Socket::from_raw_socket(raw_socket);
        net::TcpListener::from_inner(sys_common::net::TcpListener::from_inner(sock))
    }
}
#[stable(feature = "lwip_network", since = "1.64.0")]
impl FromRawSocket for net::UdpSocket {
    #[inline]
    unsafe fn from_raw_socket(raw_socket: RawSocket) -> net::UdpSocket {
        let sock = Socket::from_raw_socket(raw_socket);
        net::UdpSocket::from_inner(sys_common::net::UdpSocket::from_inner(sock))
    }
}

#[stable(feature = "lwip_network", since = "1.64.0")]
impl IntoRawSocket for net::TcpStream {
    #[inline]
    fn into_raw_socket(self) -> RawSocket {
        self.into_inner().into_socket().into_inner()
    }
}

#[stable(feature = "lwip_network", since = "1.64.0")]
impl IntoRawSocket for net::TcpListener {
    #[inline]
    fn into_raw_socket(self) -> RawSocket {
        self.into_inner().into_socket().into_inner()
    }
}

#[stable(feature = "lwip_network", since = "1.64.0")]
impl IntoRawSocket for net::UdpSocket {
    #[inline]
    fn into_raw_socket(self) -> RawSocket {
        self.into_inner().into_socket().into_inner()
    }
}

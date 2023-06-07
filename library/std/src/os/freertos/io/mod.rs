//! FreeRTOS-specific extensions to general I/O primitives.
//!
//! RawSocket is a raw socket handle. It is not safe for general use, as wrapping
//! types like Socket look after unique ownership and closing the socket on drop.
//!
//! RawSocket is used internally to pass temporary references to socket functions
//! It can also be used as an intermediary type if converting between different
//! socket representations.

#![stable(feature = "rust1", since = "1.0.0")]

mod raw;

#[stable(feature = "rust1", since = "1.0.0")]
pub use raw::*;

#[cfg(test)]
mod tests;

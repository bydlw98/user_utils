#![doc = include_str!("../README.md")]

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

use std::io;

/// `LookupResult` is a type that represents the lookup result of a record
#[derive(Debug)]
pub enum LookupResult<T> {
    /// Contains successful record
    Ok(T),

    /// No record
    NoRecord,

    /// Contains the error value
    Err(io::Error),
}

impl<T> LookupResult<T> {
    /// Returns the contained `Ok` value or a provided default
    pub fn unwrap_or(self, default: T) -> T {
        match self {
            LookupResult::Ok(t) => t,
            _ => default,
        }
    }
}

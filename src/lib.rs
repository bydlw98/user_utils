#![doc = include_str!("../README.md")]

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

use std::fmt;
use std::io;

/// An error when searching through user or group database
#[derive(Debug)]
pub enum Error {
    /// No record found
    NoRecord,

    /// An error that occured when doing I/O
    Io(io::Error),
}

impl Error {
    /// Shorthand for `Error::Io(io::Error::last_os_error())`
    #[cfg(unix)]
    fn last_os_error() -> Self {
        Self::Io(io::Error::last_os_error())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoRecord => write!(f, "No record is found"),
            Self::Io(ref err) => fmt::Display::fmt(err, f),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

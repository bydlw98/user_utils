//! Windows-specific wrappers around user and group primitives.

pub(crate) mod sys;
#[cfg(test)]
mod tests;
mod utils;

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::marker::{PhantomData, PhantomPinned};
use std::ops;

use crate::private;
use crate::Error;

/// Windows-specific extensions to [`Userid`](crate::Userid).
pub trait UseridExt: private::Sealed {
    /// Extracts the raw psid.
    fn as_raw_psid(&self) -> sys::PSID;

    /// Returns a `Userid` holding the given raw psid.
    ///
    /// # windows_sys functions used
    ///
    /// - [`IsValidSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-isvalidsid)
    fn from_raw_psid<'psid>(psid: sys::PSID) -> Option<&'psid Self>;

    /// Returns a `Userid` holding the given unvalidated raw psid
    ///
    /// # Safety
    ///
    /// This method does not check if psid is valid.
    unsafe fn from_raw_psid_unchecked<'psid>(psid: sys::PSID) -> &'psid Self;
}

/// Windows-specific extensions to [`Groupid`](crate::Groupid).
pub trait GroupidExt: private::Sealed {
    /// Extracts the raw psid.
    fn as_raw_psid(&self) -> sys::PSID;

    /// Returns a `Groupid` holding the given raw psid.
    ///
    /// # windows_sys functions used
    ///
    /// - [`IsValidSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-isvalidsid)
    fn from_raw_psid<'psid>(psid: sys::PSID) -> Option<&'psid Self>;

    /// Returns a `Userid` holding the given unvalidated raw psid
    ///
    /// # Safety
    ///
    /// This method does not check if psid is valid.
    unsafe fn from_raw_psid_unchecked<'psid>(psid: sys::PSID) -> &'psid Self;
}

pub trait GroupidBufExt: private::Sealed {
    /// Creates a new `GroupidBuf` instance containing the well-known World SID.
    ///
    /// # windows_sys functions used
    ///
    /// - [`GetSidLengthRequired`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidlengthrequired)
    /// - [`CreateWellKnownSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createwellknownsid)
    fn world() -> Result<Self, io::Error>
    where
        Self: Sized;
}

#[derive(Clone, Eq)]
pub(crate) struct Userid {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

impl Userid {
    pub fn try_clone_to_owned(&self) -> Result<UseridBuf, io::Error> {
        sys::copy_sid(self.as_raw_psid()).map(UseridBuf)
    }

    pub fn username(&self) -> Result<OsString, Error> {
        sys::lookup_account_sid(self.as_raw_psid())
    }
}

impl fmt::Display for Userid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        sys::fmt_sid(self.as_raw_psid(), f)
    }
}

impl fmt::Debug for Userid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        sys::fmt_sid(self.as_raw_psid(), f)
    }
}

impl PartialEq for Userid {
    fn eq(&self, other: &Self) -> bool {
        sys::equal_sid(self.as_raw_psid(), other.as_raw_psid())
    }
}

impl PartialEq<UseridBuf> for Userid {
    fn eq(&self, other: &UseridBuf) -> bool {
        sys::equal_sid(self.as_raw_psid(), other.as_raw_psid())
    }
}

impl private::Sealed for Userid {}
impl UseridExt for Userid {
    fn as_raw_psid(&self) -> sys::PSID {
        self as *const Self as sys::PSID
    }

    fn from_raw_psid<'psid>(psid: sys::PSID) -> Option<&'psid Self> {
        if sys::is_invalid_sid(psid) {
            None
        } else {
            Some(unsafe { Self::from_raw_psid_unchecked(psid) })
        }
    }

    unsafe fn from_raw_psid_unchecked<'psid>(psid: sys::PSID) -> &'psid Self {
        // SAFETY: Userid is just a wrapper around sys::PSID.
        // therefore converting sys::PSID to &Userid is safe.
        unsafe { &*(psid as *const sys::PSID as *const Self) }
    }
}

pub(crate) struct UseridBuf(Vec<u8>);

impl ops::Deref for UseridBuf {
    type Target = Userid;

    fn deref(&self) -> &Self::Target {
        unsafe { Userid::from_raw_psid_unchecked(self.0.as_ptr() as sys::PSID) }
    }
}

impl fmt::Display for UseridBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        sys::fmt_sid(self.as_raw_psid(), f)
    }
}

impl fmt::Debug for UseridBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        sys::fmt_sid(self.as_raw_psid(), f)
    }
}

impl PartialEq for UseridBuf {
    fn eq(&self, other: &Self) -> bool {
        sys::equal_sid(self.as_raw_psid(), other.as_raw_psid())
    }
}

impl PartialEq<Userid> for UseridBuf {
    fn eq(&self, other: &Userid) -> bool {
        sys::equal_sid(self.as_raw_psid(), other.as_raw_psid())
    }
}

impl Eq for UseridBuf {}

#[derive(Clone, Eq)]
pub(crate) struct Groupid {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

impl Groupid {
    pub fn try_clone_to_owned(&self) -> Result<GroupidBuf, io::Error> {
        sys::copy_sid(self.as_raw_psid()).map(GroupidBuf)
    }

    pub fn groupname(&self) -> Result<OsString, Error> {
        sys::lookup_account_sid(self.as_raw_psid())
    }
}

impl fmt::Display for Groupid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        sys::fmt_sid(self.as_raw_psid(), f)
    }
}

impl fmt::Debug for Groupid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        sys::fmt_sid(self.as_raw_psid(), f)
    }
}

impl PartialEq for Groupid {
    fn eq(&self, other: &Self) -> bool {
        sys::equal_sid(self.as_raw_psid(), other.as_raw_psid())
    }
}

impl private::Sealed for Groupid {}
impl GroupidExt for Groupid {
    fn as_raw_psid(&self) -> sys::PSID {
        self as *const Self as sys::PSID
    }

    fn from_raw_psid<'psid>(psid: sys::PSID) -> Option<&'psid Self> {
        if sys::is_invalid_sid(psid) {
            None
        } else {
            Some(unsafe { Self::from_raw_psid_unchecked(psid) })
        }
    }

    unsafe fn from_raw_psid_unchecked<'psid>(psid: sys::PSID) -> &'psid Self {
        // SAFETY: Groupid is just a wrapper around sys::PSID.
        // therefore converting sys::PSID to &Groupid is safe.
        unsafe { &*(psid as *const sys::PSID as *const Self) }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GroupidBuf(Vec<u8>);

impl fmt::Display for GroupidBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        sys::fmt_sid(self.as_raw_psid(), f)
    }
}

impl ops::Deref for GroupidBuf {
    type Target = Groupid;

    fn deref(&self) -> &Self::Target {
        unsafe { Groupid::from_raw_psid_unchecked(self.0.as_ptr() as sys::PSID) }
    }
}

impl private::Sealed for GroupidBuf {}
impl GroupidBufExt for GroupidBuf {
    fn world() -> Result<Self, io::Error> {
        sys::create_world_sid().map(GroupidBuf)
    }
}

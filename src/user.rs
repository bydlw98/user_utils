use std::ffi::OsString;
use std::fmt;
use std::io;
use std::ops;

#[cfg(unix)]
use crate::os::unix as os_impl;
#[cfg(windows)]
use crate::os::windows as os_impl;
use crate::private;
use crate::Error;

#[derive(Clone, PartialEq, Eq)]
pub struct Userid(os_impl::Userid);

impl Userid {
    /// Creates a new [`UseridBuf`] instance.
    #[inline]
    pub fn try_clone_to_owned(&self) -> Result<UseridBuf, io::Error> {
        self.0.try_clone_to_owned().map(UseridBuf)
    }

    /// Searches user database and returns the login name of user.
    pub fn username(&self) -> Result<OsString, Error> {
        self.0.username()
    }
}

impl fmt::Display for Userid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Userid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl PartialEq<UseridBuf> for Userid {
    fn eq(&self, other: &UseridBuf) -> bool {
        self.0 == other.0
    }
}

impl private::Sealed for Userid {}

#[cfg(unix)]
impl crate::os::unix::UseridExt for Userid {
    fn as_raw_uid(&self) -> libc::uid_t {
        self.0.as_raw_uid()
    }

    fn from_raw_uid(uid: &libc::uid_t) -> &Self {
        // SAFETY: Userid is just a wrapper around libc::uid_t.
        // therefore converting &libc::uid_t to &Userid is safe.
        unsafe { &*(uid as *const libc::uid_t as *const crate::os::unix::Userid as *const Userid) }
    }

    fn lookup_passwd(&self) -> Result<crate::os::unix::Passwd, Error> {
        self.0.lookup_passwd()
    }
}

#[cfg(windows)]
impl crate::os::windows::UseridExt for Userid {
    fn as_raw_psid(&self) -> crate::os::windows::sys::PSID {
        self.0.as_raw_psid()
    }

    fn from_raw_psid<'psid>(psid: os_impl::sys::PSID) -> Option<&'psid Self> {
        let os_impl_userid = os_impl::Userid::from_raw_psid(psid)?;

        Some(unsafe { &*(os_impl_userid as *const crate::os::windows::Userid as *const Userid) })
    }

    unsafe fn from_raw_psid_unchecked<'psid>(psid: os_impl::sys::PSID) -> &'psid Self {
        // SAFETY: Userid is just a wrapper around sys::PSID.
        // therefore converting sys::PSID to &Userid is safe.
        unsafe { &*(psid as *const crate::os::windows::Userid as *const Userid) }
    }
}

#[derive(PartialEq, Eq)]
pub struct UseridBuf(os_impl::UseridBuf);

impl fmt::Display for UseridBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for UseridBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl PartialEq<Userid> for UseridBuf {
    fn eq(&self, other: &Userid) -> bool {
        self.0 == other.0
    }
}

impl ops::Deref for UseridBuf {
    type Target = Userid;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Userid is just a wrapper around os_impl::Userid.
        // therefore converting &os_impl::Userid to &Userid is safe.
        unsafe { &*(self.0.deref() as *const os_impl::Userid as *const Userid) }
    }
}

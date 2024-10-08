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

/// A new type pattern around a `borrowed` platform-native group id.
#[derive(PartialEq, Eq)]
pub struct Groupid(os_impl::Groupid);

impl Groupid {
    /// Creates a new [`GroupidBuf`] instance.
    #[inline]
    pub fn try_clone(&self) -> Result<GroupidBuf, io::Error> {
        self.0.try_clone().map(GroupidBuf)
    }

    /// Searches group database and returns the name of group.
    pub fn name(&self) -> Result<OsString, Error> {
        self.0.name()
    }
}

impl fmt::Display for Groupid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Groupid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl PartialEq<GroupidBuf> for Groupid {
    fn eq(&self, other: &GroupidBuf) -> bool {
        self.0 == other.0
    }
}

impl private::Sealed for Groupid {}

#[cfg(unix)]
impl crate::os::unix::GroupidExt for Groupid {
    fn as_raw_gid(&self) -> libc::gid_t {
        self.0.as_raw_gid()
    }

    fn from_raw_gid(gid: &libc::gid_t) -> &Self {
        // SAFETY: Groupid is just a wrapper around libc::gid_t.
        // therefore converting &libc::gid_t to &Groupid is safe.
        unsafe {
            &*(gid as *const libc::gid_t as *const crate::os::unix::Groupid as *const Groupid)
        }
    }

    fn lookup_group(&self) -> Result<crate::os::unix::Group, Error> {
        self.0.lookup_group()
    }
}

#[cfg(windows)]
impl crate::os::windows::GroupidExt for Groupid {
    fn as_raw_psid(&self) -> os_impl::PSID {
        self.0.as_raw_psid()
    }

    fn from_raw_psid<'psid>(psid: os_impl::PSID) -> Option<&'psid Self> {
        let os_impl_groupid = os_impl::Groupid::from_raw_psid(psid)?;

        Some(unsafe { &*(os_impl_groupid as *const os_impl::Groupid as *const Self) })
    }

    unsafe fn from_raw_psid_unchecked<'psid>(psid: os_impl::PSID) -> &'psid Self {
        // SAFETY: Groupid is just a wrapper around sys::PSID.
        // therefore converting sys::PSID to &Groupid is safe.
        unsafe {
            &*(os_impl::Groupid::from_raw_psid_unchecked(psid) as *const os_impl::Groupid
                as *const Self)
        }
    }
}

/// A new type pattern around an `owned` platform-native group id.
#[derive(PartialEq, Eq)]
pub struct GroupidBuf(os_impl::GroupidBuf);

impl fmt::Display for GroupidBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for GroupidBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl PartialEq<Groupid> for GroupidBuf {
    fn eq(&self, other: &Groupid) -> bool {
        self.0 == other.0
    }
}

impl ops::Deref for GroupidBuf {
    type Target = Groupid;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Groupid is just a wrapper around os_impl::Groupid.
        // therefore converting &os_impl::Groupid to &Groupid is safe.
        unsafe { &*(self.0.deref() as *const os_impl::Groupid as *const Groupid) }
    }
}

impl private::Sealed for GroupidBuf {}

#[cfg(windows)]
impl crate::os::windows::GroupidBufExt for GroupidBuf {
    fn world() -> Result<Self, io::Error> {
        let os_impl_groupidbuf = os_impl::GroupidBuf::world()?;

        Ok(GroupidBuf(os_impl_groupidbuf))
    }
}

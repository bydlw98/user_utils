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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groupid(os_impl::Groupid);

impl Groupid {
    /// Creates a new [`GroupidBuf`] instance.
    #[inline]
    pub fn try_clone_to_owned(&self) -> Result<GroupidBuf, io::Error> {
        self.0.try_clone_to_owned().map(GroupidBuf)
    }

    /// Searches group database and returns the name of group.
    pub fn groupname(&self) -> Result<OsString, Error> {
        self.0.groupname()
    }
}

impl fmt::Display for Groupid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<GroupidBuf> for Groupid {
    fn eq(&self, other: &GroupidBuf) -> bool {
        self.0.eq(&other.0)
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
    fn as_raw_psid(&self) -> os_impl::sys::PSID {
        self.0.as_raw_psid()
    }

    fn from_raw_psid<'psid>(psid: os_impl::sys::PSID) -> Option<&'psid Self> {
        use crate::os::windows::UseridExt;

        let os_impl_userid = os_impl::Userid::from_raw_psid(psid)?;

        Some(unsafe {
            &*(os_impl_userid as *const crate::os::windows::Userid
                as *const crate::os::windows::Groupid as *const Groupid)
        })
    }

    unsafe fn from_raw_psid_unchecked<'psid>(psid: os_impl::sys::PSID) -> &'psid Self {
        // SAFETY: Groupid is just a wrapper around sys::PSID.
        // therefore converting sys::PSID to &Userid is safe.
        unsafe {
            &*(psid as *const crate::os::windows::Userid as *const crate::os::windows::Groupid
                as *const Groupid)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct GroupidBuf(os_impl::GroupidBuf);

impl ops::Deref for GroupidBuf {
    type Target = Groupid;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Groupid is just a wrapper around os_impl::Groupid.
        // therefore converting &os_impl::Groupid to &Groupid is safe.
        unsafe { &*(self.0.deref() as *const os_impl::Groupid as *const Groupid) }
    }
}

impl PartialEq<Groupid> for GroupidBuf {
    fn eq(&self, other: &Groupid) -> bool {
        other.eq(self)
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

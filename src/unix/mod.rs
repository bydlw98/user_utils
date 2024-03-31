//! Unix-specific wrappers around user and group primitives

#[cfg(test)]
mod tests;

use super::LookupResult;

use std::ffi::{c_char, CStr, OsStr, OsString};
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::ptr;

/// A borrowed uid.
///
/// This has a lifetime parameter to tie it to the lifetime of something that owns the uid.
#[derive(Clone, Copy)]
pub struct BorrowedUid<'uid> {
    raw_uid: libc::uid_t,
    _phantom: PhantomData<&'uid OwnedUid>,
}

impl BorrowedUid<'_> {
    /// Returns a `BorrowedUid` holding the given raw uid
    #[inline]
    pub fn borrow_raw(uid: libc::uid_t) -> Self {
        Self {
            raw_uid: uid,
            _phantom: PhantomData,
        }
    }

    /// Creates a new `OwnedUid` instance
    #[inline]
    pub fn try_clone_to_owned(&self) -> Result<OwnedUid, io::Error> {
        Ok(OwnedUid {
            raw_uid: self.raw_uid,
        })
    }

    /// Searches user database and returns the passwd record of user
    ///
    /// # libc functions used
    ///
    /// - [`getpwuid_r`](https://pubs.opengroup.org/onlinepubs/7908799/xsh/getpwuid_r.html)
    pub fn lookup_passwd(&self) -> LookupResult<Passwd> {
        Passwd::lookup_by_uid(self.raw_uid)
    }

    /// Searches user database and returns the login name of user
    ///
    /// # libc functions used
    ///
    /// - [`getpwuid_r`](https://pubs.opengroup.org/onlinepubs/7908799/xsh/getpwuid_r.html)
    pub fn lookup_username(&self) -> LookupResult<OsString> {
        match self.lookup_passwd() {
            LookupResult::Ok(pwd) => {
                let pw_name = unsafe { CStr::from_ptr(pwd.raw_pwd.pw_name) };
                let vec = pw_name.to_bytes().to_vec();

                LookupResult::Ok(OsString::from_vec(vec))
            }
            LookupResult::NoRecord => LookupResult::NoRecord,
            LookupResult::Err(err) => LookupResult::Err(err),
        }
    }
}

impl fmt::Display for BorrowedUid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_uid)
    }
}

impl fmt::Debug for BorrowedUid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_uid)
    }
}

impl PartialEq for BorrowedUid<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.raw_uid.eq(&other.raw_uid)
    }
}

impl PartialEq<OwnedUid> for BorrowedUid<'_> {
    #[inline]
    fn eq(&self, other: &OwnedUid) -> bool {
        self.raw_uid.eq(&other.raw_uid)
    }
}

impl Eq for BorrowedUid<'_> {}

/// An owned uid
#[derive(PartialEq, Eq)]
pub struct OwnedUid {
    raw_uid: libc::uid_t,
}

impl PartialEq<BorrowedUid<'_>> for OwnedUid {
    #[inline]
    fn eq(&self, other: &BorrowedUid<'_>) -> bool {
        self.raw_uid.eq(&other.raw_uid)
    }
}

/// Metadata information about a user
///
/// Newtype pattern around [`passwd`](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/pwd.h.html)
pub struct Passwd {
    raw_pwd: libc::passwd,
    buf: Vec<c_char>,
}

impl Passwd {
    /// Returns the login name of user
    pub fn name(&self) -> &OsStr {
        let pw_name = unsafe { CStr::from_ptr(self.raw_pwd.pw_name) };

        OsStr::from_bytes(pw_name.to_bytes())
    }

    /// Returns the id of user
    #[inline]
    pub fn uid(&self) -> BorrowedUid<'_> {
        BorrowedUid::borrow_raw(self.raw_pwd.pw_uid)
    }

    /// Returns the primary group id of user
    #[inline]
    pub fn gid(&self) -> BorrowedGid<'_> {
        BorrowedGid::borrow_raw(self.raw_pwd.pw_gid)
    }

    /// Returns the initial working directory of user
    pub fn dir(&self) -> &OsStr {
        let pw_dir = unsafe { CStr::from_ptr(self.raw_pwd.pw_dir) };

        OsStr::from_bytes(pw_dir.to_bytes())
    }

    /// Returns the login shell of user
    pub fn shell(&self) -> &OsStr {
        let pw_shell = unsafe { CStr::from_ptr(self.raw_pwd.pw_shell) };

        OsStr::from_bytes(pw_shell.to_bytes())
    }

    /// Return user's raw passwd struct record
    #[inline]
    pub fn as_raw_passwd(&self) -> &libc::passwd {
        &self.raw_pwd
    }

    pub(crate) fn lookup_by_uid(uid: libc::uid_t) -> LookupResult<Self> {
        let mut buflen = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
        if buflen == -1 {
            buflen = 1024;
        }
        let mut passwd = Self {
            raw_pwd: unsafe { mem::zeroed() },
            buf: vec![0; buflen as usize],
        };
        let mut result: *mut libc::passwd = ptr::null_mut();

        unsafe {
            let return_code = libc::getpwuid_r(
                uid,
                &mut passwd.raw_pwd,
                passwd.buf.as_mut_ptr(),
                buflen as usize,
                &mut result,
            );

            // On success, return_code is 0
            if return_code == 0 {
                // If passwd record is found for uid, result is a pointer to pwd
                if result == &mut passwd.raw_pwd {
                    LookupResult::Ok(passwd)
                } else {
                    LookupResult::NoRecord
                }
            } else {
                LookupResult::Err(io::Error::last_os_error())
            }
        }
    }
}

impl fmt::Debug for Passwd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passwd")
            .field("pw_name", &self.name())
            .field("pw_uid", &self.uid())
            .field("pw_gid", &self.gid())
            .field("pw_dir", &self.dir())
            .field("pw_shell", &self.shell())
            .finish_non_exhaustive()
    }
}

/// A borrowed gid.
///
/// This has a lifetime parameter to tie it to the lifetime of something that owns the gid.
#[derive(Clone, Copy)]
pub struct BorrowedGid<'gid> {
    raw_gid: libc::gid_t,
    _phantom: PhantomData<&'gid OwnedGid>,
}

impl BorrowedGid<'_> {
    /// Returns a `BorrowedGid` holding the given raw gid
    #[inline]
    pub fn borrow_raw(gid: libc::gid_t) -> Self {
        Self {
            raw_gid: gid,
            _phantom: PhantomData,
        }
    }

    /// Creates a new `OwnedGid` instance
    #[inline]
    pub fn try_clone_to_owned(&self) -> Result<OwnedGid, io::Error> {
        Ok(OwnedGid {
            raw_gid: self.raw_gid,
        })
    }

    /// Searches group database and returns the group record of group
    ///
    /// # libc functions used
    ///
    /// - [`getgrgid_r`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrgid_r.html)
    pub fn lookup_group(&self) -> LookupResult<Group> {
        Group::lookup_by_gid(self.raw_gid)
    }

    /// Searches group database and returns the name of group
    ///
    /// # libc functions used
    ///
    /// - [`getgrgid_r`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrgid_r.html)
    pub fn lookup_groupname(&self) -> LookupResult<OsString> {
        match self.lookup_group() {
            LookupResult::Ok(grp) => {
                let gr_name = unsafe { CStr::from_ptr(grp.raw_group.gr_name) };
                let vec = gr_name.to_bytes().to_vec();

                LookupResult::Ok(OsString::from_vec(vec))
            }
            LookupResult::NoRecord => LookupResult::NoRecord,
            LookupResult::Err(err) => LookupResult::Err(err),
        }
    }
}

impl fmt::Display for BorrowedGid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_gid)
    }
}

impl fmt::Debug for BorrowedGid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_gid)
    }
}

impl PartialEq for BorrowedGid<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.raw_gid.eq(&other.raw_gid)
    }
}

impl Eq for BorrowedGid<'_> {}

impl PartialEq<OwnedGid> for BorrowedGid<'_> {
    #[inline]
    fn eq(&self, other: &OwnedGid) -> bool {
        self.raw_gid.eq(&other.raw_gid)
    }
}

/// An owned gid
#[derive(PartialEq, Eq)]
pub struct OwnedGid {
    raw_gid: libc::gid_t,
}

impl fmt::Display for OwnedGid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_gid)
    }
}

impl fmt::Debug for OwnedGid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_gid)
    }
}

impl PartialEq<BorrowedGid<'_>> for OwnedGid {
    #[inline]
    fn eq(&self, other: &BorrowedGid<'_>) -> bool {
        self.raw_gid.eq(&other.raw_gid)
    }
}

/// Metadata information about a group
///
/// Newtype pattern around [`group`](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/grp.h.html)
pub struct Group {
    raw_group: libc::group,
    buf: Vec<c_char>,
}

impl Group {
    /// Returns the name of group
    pub fn name(&self) -> &OsStr {
        let gr_name = unsafe { CStr::from_ptr(self.raw_group.gr_name) };

        OsStr::from_bytes(gr_name.to_bytes())
    }

    /// Returns the id of group
    #[inline]
    pub fn gid(&self) -> BorrowedGid<'_> {
        BorrowedGid::borrow_raw(self.raw_group.gr_gid)
    }

    /// Returns the usernames in group
    pub fn mem(&self) -> Vec<OsString> {
        let mut member_usernames: Vec<OsString> = Vec::new();
        let mut i: isize = 0;

        loop {
            unsafe {
                let username_ptr = self.raw_group.gr_mem.offset(i);
                if username_ptr.is_null() || (*username_ptr).is_null() {
                    break;
                } else {
                    let username_cstr = CStr::from_ptr(*username_ptr);
                    member_usernames.push(OsString::from_vec(username_cstr.to_bytes().to_vec()));
                    i += 1;
                }
            }
        }

        member_usernames
    }

    /// Returns the raw group struct record
    #[inline]
    pub fn as_raw_group(&self) -> &libc::group {
        &self.raw_group
    }

    pub(crate) fn lookup_by_gid(gid: libc::gid_t) -> LookupResult<Self> {
        let mut buflen = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
        if buflen == -1 {
            buflen = 1024;
        }

        let mut grp = Self {
            raw_group: unsafe { mem::zeroed() },
            buf: vec![0; buflen as usize],
        };
        let mut result: *mut libc::group = ptr::null_mut();

        unsafe {
            let return_code = libc::getgrgid_r(
                gid,
                &mut grp.raw_group,
                grp.buf.as_mut_ptr(),
                buflen as usize,
                &mut result,
            );

            // On success, return_code is 0
            if return_code == 0 {
                // If passwd record is found for uid, result is a pointer to pwd
                if result == &mut grp.raw_group {
                    LookupResult::Ok(grp)
                } else {
                    LookupResult::NoRecord
                }
            } else {
                LookupResult::Err(io::Error::last_os_error())
            }
        }
    }
}

impl fmt::Debug for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Group")
            .field("gr_name", &self.name())
            .field("gr_gid", &self.gid())
            .field("gr_mem", &self.mem())
            .finish_non_exhaustive()
    }
}

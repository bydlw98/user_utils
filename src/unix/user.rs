use std::ffi::{c_char, CStr, OsStr, OsString};
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::ptr;

use super::BorrowedGid;
use crate::Error;

/// A trait to borrow the uid
pub trait AsUid {
    /// Borrows the uid.
    fn as_uid(&self) -> BorrowedUid<'_>;
}

/// A trait to extract the raw uid.
pub trait AsRawUid {
    /// Extracts the raw uid.
    fn as_raw_uid(&self) -> libc::uid_t;
}

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
    pub fn lookup_passwd(&self) -> Result<Passwd, Error> {
        Passwd::lookup_by_uid(self.raw_uid)
    }

    /// Searches user database and returns the login name of user
    ///
    /// # libc functions used
    ///
    /// - [`getpwuid_r`](https://pubs.opengroup.org/onlinepubs/7908799/xsh/getpwuid_r.html)
    pub fn lookup_username(&self) -> Result<OsString, Error> {
        let pwd = self.lookup_passwd()?;
        let pw_name = unsafe { CStr::from_ptr(pwd.raw_pwd.pw_name) };
        let vec = pw_name.to_bytes().to_vec();

        Ok(OsString::from_vec(vec))
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

impl AsUid for BorrowedUid<'_> {
    #[inline]
    fn as_uid(&self) -> BorrowedUid<'_> {
        *self
    }
}

impl AsRawUid for BorrowedUid<'_> {
    #[inline]
    fn as_raw_uid(&self) -> libc::uid_t {
        self.raw_uid
    }
}

/// An owned uid
#[derive(PartialEq, Eq)]
pub struct OwnedUid {
    raw_uid: libc::uid_t,
}

impl fmt::Display for OwnedUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_uid)
    }
}

impl fmt::Debug for OwnedUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_uid)
    }
}

impl PartialEq<BorrowedUid<'_>> for OwnedUid {
    #[inline]
    fn eq(&self, other: &BorrowedUid<'_>) -> bool {
        self.raw_uid.eq(&other.raw_uid)
    }
}

impl AsUid for OwnedUid {
    #[inline]
    fn as_uid(&self) -> BorrowedUid<'_> {
        BorrowedUid::borrow_raw(self.raw_uid)
    }
}

impl AsRawUid for OwnedUid {
    #[inline]
    fn as_raw_uid(&self) -> libc::uid_t {
        self.raw_uid
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

    pub(crate) fn lookup_by_uid(uid: libc::uid_t) -> Result<Self, Error> {
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
                    Ok(passwd)
                } else {
                    Err(Error::NoRecord)
                }
            } else {
                Err(Error::last_os_error())
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::process::Command;

    #[test]
    fn test_passwd_lookup_by_uid_ok() {
        if let Ok(pwd) = Passwd::lookup_by_uid(unsafe { libc::getuid() }) {
            let id_un_stdout = Command::new("id").arg("-un").output().unwrap().stdout;
            assert_eq!(
                pwd.name().as_bytes(),
                &id_un_stdout[0..id_un_stdout.len() - 1]
            );

            assert_eq!(
                pwd.uid(),
                BorrowedUid::borrow_raw(unsafe { libc::getuid() })
            );

            assert_eq!(
                pwd.gid(),
                BorrowedGid::borrow_raw(unsafe { libc::getgid() })
            );

            // Using $HOME to get home dir and $SHELL to get login shell does not work
            // in github actions. This causes the 2 asserts below to fail
            // assert_eq!(pwd.dir(), env::var_os("HOME").unwrap());
            // assert_eq!(pwd.shell(), env::var_os("SHELL").unwrap());
        } else {
            panic!();
        }
    }

    #[test]
    fn test_passwd_lookup_by_uid_norecord() {
        let result = Passwd::lookup_by_uid(libc::uid_t::MAX - 3);

        assert!(matches!(result, Err(Error::NoRecord)));
    }
}

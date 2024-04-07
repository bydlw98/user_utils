use std::ffi::{c_char, CStr, OsStr, OsString};
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::ptr;

use crate::Error;

/// A trait to borrow the gid
pub trait AsGid {
    /// Borrows the gid.
    fn as_gid(&self) -> BorrowedGid<'_>;
}

/// A trait to extract the raw gid.
pub trait AsRawGid {
    /// Extracts the raw gid.
    fn as_raw_gid(&self) -> libc::gid_t;
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
    pub fn lookup_group(&self) -> Result<Group, Error> {
        Group::lookup_by_gid(self.raw_gid)
    }

    /// Searches group database and returns the name of group
    ///
    /// # libc functions used
    ///
    /// - [`getgrgid_r`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrgid_r.html)
    pub fn lookup_groupname(&self) -> Result<OsString, Error> {
        let grp = self.lookup_group()?;
        let gr_name = unsafe { CStr::from_ptr(grp.raw_group.gr_name) };
        let vec = gr_name.to_bytes().to_vec();

        Ok(OsString::from_vec(vec))
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

impl AsGid for BorrowedGid<'_> {
    #[inline]
    fn as_gid(&self) -> BorrowedGid<'_> {
        *self
    }
}

impl AsRawGid for BorrowedGid<'_> {
    #[inline]
    fn as_raw_gid(&self) -> libc::gid_t {
        self.raw_gid
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

impl AsGid for OwnedGid {
    #[inline]
    fn as_gid(&self) -> BorrowedGid<'_> {
        BorrowedGid::borrow_raw(self.raw_gid)
    }
}

impl AsRawGid for OwnedGid {
    #[inline]
    fn as_raw_gid(&self) -> libc::gid_t {
        self.raw_gid
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

    pub(crate) fn lookup_by_gid(gid: libc::gid_t) -> Result<Self, Error> {
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
                    Ok(grp)
                } else {
                    Err(Error::NoRecord)
                }
            } else {
                Err(Error::last_os_error())
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::process::Command;

    #[test]
    fn test_group_lookup_by_gid_ok() {
        if let Ok(grp) = Group::lookup_by_gid(unsafe { libc::getgid() }) {
            let id_gn_stdout = Command::new("id").arg("-gn").output().unwrap().stdout;
            assert_eq!(
                grp.name().as_bytes(),
                &id_gn_stdout[0..id_gn_stdout.len() - 1]
            );

            assert_eq!(
                grp.gid(),
                BorrowedGid::borrow_raw(unsafe { libc::getgid() })
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn test_group_lookup_by_gid_norecord() {
        let result = Group::lookup_by_gid(libc::gid_t::MAX - 3);

        assert!(matches!(result, Err(Error::NoRecord)));
    }
}

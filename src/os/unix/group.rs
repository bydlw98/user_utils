use std::ffi::{c_char, CStr, OsStr, OsString};
use std::fmt;
use std::io;
use std::mem;
use std::ops;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::ptr;

use crate::private;
use crate::Error;

/// Unix-specific extensions to [`Groupid`](crate::Groupid).
pub trait GroupidExt: private::Sealed {
    /// Extracts the raw gid.
    fn as_raw_gid(&self) -> libc::gid_t;

    /// Returns a `Groupid` holding the given raw gid.
    fn from_raw_gid(gid: &libc::gid_t) -> &Self;

    /// Searches group database and returns the group record of group.
    ///
    /// # libc functions used
    ///
    /// - [`getgrgid_r`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrgid_r.html)
    fn lookup_group(&self) -> Result<Group, Error>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Groupid {
    raw_gid: libc::gid_t,
}

impl Groupid {
    #[inline]
    pub fn try_clone(&self) -> Result<GroupidBuf, io::Error> {
        Ok(GroupidBuf {
            raw_gid: self.raw_gid,
        })
    }

    pub fn name(&self) -> Result<OsString, Error> {
        get_name_by_gid(self.raw_gid)
    }
}

impl fmt::Display for Groupid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_gid)
    }
}

impl fmt::Debug for Groupid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_gid)
    }
}

impl PartialEq<GroupidBuf> for Groupid {
    fn eq(&self, other: &GroupidBuf) -> bool {
        self.raw_gid == other.raw_gid
    }
}

impl private::Sealed for Groupid {}
impl GroupidExt for Groupid {
    fn as_raw_gid(&self) -> libc::gid_t {
        self.raw_gid
    }

    fn from_raw_gid(gid: &libc::gid_t) -> &Self {
        // SAFETY: Groupid is just a wrapper around libc::gid_t.
        // therefore converting &libc::gid_t to &Groupid is safe.
        unsafe { &*(gid as *const libc::gid_t as *const Self) }
    }

    fn lookup_group(&self) -> Result<Group, Error> {
        get_gr_by_gid(self.raw_gid)
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct GroupidBuf {
    raw_gid: libc::gid_t,
}

impl fmt::Display for GroupidBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_gid)
    }
}

impl fmt::Debug for GroupidBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_gid)
    }
}

impl PartialEq<Groupid> for GroupidBuf {
    fn eq(&self, other: &Groupid) -> bool {
        self.raw_gid == other.raw_gid
    }
}

impl ops::Deref for GroupidBuf {
    type Target = Groupid;

    fn deref(&self) -> &Self::Target {
        Groupid::from_raw_gid(&self.raw_gid)
    }
}

/// Metadata information about a group.
///
/// Newtype pattern around [`group`](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/grp.h.html)
pub struct Group {
    raw_group: libc::group,
    buf: Vec<c_char>,
}

impl Group {
    /// Returns the name of group.
    pub fn name(&self) -> &OsStr {
        let gr_name = unsafe { CStr::from_ptr(self.raw_group.gr_name) };

        OsStr::from_bytes(gr_name.to_bytes())
    }

    /// Returns the id of group.
    #[inline]
    pub fn gid(&self) -> &crate::Groupid {
        crate::Groupid::from_raw_gid(&self.raw_group.gr_gid)
    }

    /// Returns the usernames in group.
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

    /// Returns the raw group struct record.
    #[inline]
    pub fn as_raw_group(&self) -> &libc::group {
        &self.raw_group
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

/// Searches group database and returns the name of group.
///
/// # libc functions used
///
/// - [`getgrgid_r`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrgid_r.html)
pub fn get_name_by_gid(gid: libc::gid_t) -> Result<OsString, Error> {
    let grp = get_gr_by_gid(gid)?;
    let gr_name = unsafe { CStr::from_ptr(grp.raw_group.gr_name) };
    let vec = gr_name.to_bytes().to_vec();

    Ok(OsString::from_vec(vec))
}

/// Searches group database and returns the group record of group.
///
/// # libc functions used
///
/// - [`getgrgid_r`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrgid_r.html)
pub fn get_gr_by_gid(gid: libc::gid_t) -> Result<Group, Error> {
    let mut buflen = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if buflen == -1 {
        buflen = 1024;
    }

    let mut grp = Group {
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
            // If group record is found for gid, result is a pointer to grp
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

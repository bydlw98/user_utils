//! Windows-specific wrappers around user and group primitives.

pub(crate) mod sys;
mod utils;

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::mem::MaybeUninit;
use std::ops;
use std::ptr;
use std::slice;

use crate::Error;

/// Windows-specific extensions to [`Userid`](crate::Userid).
pub trait UseridExt {
    /// Extracts the raw psid.
    fn as_raw_psid(&self) -> sys::PSID;

    /// Returns a `Userid` holding the given raw psid.
    fn from_raw_psid<'psid>(psid: sys::PSID) -> Option<&'psid Self>;

    /// Returns a `Userid` holding the given unvalidated raw psid
    ///
    /// # Safety
    ///
    /// This method does not check if psid is valid.
    unsafe fn from_raw_psid_unchecked<'psid>(psid: sys::PSID) -> &'psid Self;
}

pub trait GroupidExt {
    /// Extracts the raw psid.
    fn as_raw_psid(&self) -> sys::PSID;

    /// Returns a `Groupid` holding the given raw psid.
    fn from_raw_psid<'psid>(psid: sys::PSID) -> Option<&'psid Self>;

    /// Returns a `Userid` holding the given unvalidated raw psid
    ///
    /// # Safety
    ///
    /// This method does not check if psid is valid.
    unsafe fn from_raw_psid_unchecked<'psid>(psid: sys::PSID) -> &'psid Self;
}

#[derive(Clone, Copy)]
pub(crate) struct Userid {
    raw_psid: sys::PSID,
}

impl Userid {
    /// # windows_sys functions used
    ///
    /// - [`GetLengthSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getlengthsid)
    /// - [`CopySid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-copysid)
    pub fn try_clone_to_owned(&self) -> Result<UseridBuf, io::Error> {
        let sid_length = unsafe { sys::GetLengthSid(self.raw_psid) };
        let mut buf: Vec<u8> = vec![0; sid_length as usize];
        let return_code =
            unsafe { sys::CopySid(sid_length, buf.as_mut_ptr() as sys::PSID, self.raw_psid) };

        // On success, return_code is non-zero
        if return_code != 0 {
            Ok(UseridBuf { buf })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    // Searches database and returns the account name of SID in a `DOMAIN\name` format
    ///
    /// # windows_sys functions used
    ///
    /// - [`LookupAccountSidW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsidw)
    pub fn username(&self) -> Result<OsString, Error> {
        let mut wide_name_length: u32 = 32;
        let mut wide_domain_length: u32 = 32;
        let mut wide_name_buf: [u16; 32] = [0; 32];
        let mut wide_domain_buf: [u16; 32] = [0; 32];
        let mut sid_name_use = sys::SidTypeUnknown;

        let return_code = unsafe {
            sys::LookupAccountSidW(
                ptr::null(),
                self.raw_psid,
                wide_name_buf.as_mut_ptr(),
                &mut wide_name_length,
                wide_domain_buf.as_mut_ptr(),
                &mut wide_domain_length,
                &mut sid_name_use,
            )
        };

        // If LookupAccountSidW succeeds, return_code is non-zero
        if return_code != 0 {
            Ok(utils::accountname_from_wide_domain_and_name(
                &wide_domain_buf,
                &wide_name_buf,
            ))
        }
        // If GetLastError() returns ERROR_NONE_MAPPED, means
        // unable to get the name of SID
        else if unsafe { sys::GetLastError() } == sys::ERROR_NONE_MAPPED {
            Err(Error::NoRecord)
        } else {
            // Retry lookup SID name with correct size
            let mut wide_name = vec![0; wide_name_length as usize];
            let mut wide_domain = vec![0; wide_domain_length as usize];

            let return_code = unsafe {
                sys::LookupAccountSidW(
                    ptr::null(),
                    self.raw_psid,
                    wide_name.as_mut_ptr(),
                    &mut wide_name_length,
                    wide_domain.as_mut_ptr(),
                    &mut wide_domain_length,
                    &mut sid_name_use,
                )
            };

            // If LookupAccountSidW succeeds, return_code is non-zero
            if return_code != 0 {
                Ok(utils::accountname_from_wide_domain_and_name(
                    &wide_domain_buf,
                    &wide_name_buf,
                ))
            } else {
                Err(Error::NoRecord)
            }
        }
    }

    /// Converts an SID to a displayable string format
    ///
    /// # windows_sys functions used
    ///
    /// - [`ConvertSidToStringSidW`](https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtostringsidw)
    fn convert_to_string_sid(&self) -> Result<String, io::Error> {
        let mut wide_cstring_sid = MaybeUninit::<*mut u16>::uninit();
        let return_code =
            unsafe { sys::ConvertSidToStringSidW(self.raw_psid, wide_cstring_sid.as_mut_ptr()) };

        // On success, return_code is non-zero
        if return_code != 0 {
            let wide_cstring_sid = unsafe { wide_cstring_sid.assume_init() };
            let wide_cstring_sid_len = unsafe { libc::wcslen(wide_cstring_sid) };
            let wide_cstring_sid_slice =
                unsafe { slice::from_raw_parts(wide_cstring_sid, wide_cstring_sid_len) };
            let string_sid = String::from_utf16_lossy(wide_cstring_sid_slice);
            unsafe { sys::LocalFree(wide_cstring_sid as sys::HLOCAL) };

            Ok(string_sid)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl fmt::Display for Userid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.convert_to_string_sid() {
            Ok(string_sid) => write!(f, "{}", string_sid),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl fmt::Debug for Userid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.convert_to_string_sid() {
            Ok(string_sid) => write!(f, "{}", string_sid),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl PartialEq for Userid {
    fn eq(&self, other: &Self) -> bool {
        unsafe { sys::EqualSid(self.raw_psid, other.raw_psid) != 0 }
    }
}

impl PartialEq<UseridBuf> for Userid {
    fn eq(&self, other: &UseridBuf) -> bool {
        self.as_raw_psid() == other.buf.as_ptr() as sys::PSID
    }
}

impl Eq for Userid {}

impl UseridExt for Userid {
    fn as_raw_psid(&self) -> sys::PSID {
        self.raw_psid
    }

    fn from_raw_psid<'psid>(psid: sys::PSID) -> Option<&'psid Self> {
        if psid.is_null() || (unsafe { sys::IsValidSid(psid) } == 0) {
            None
        } else {
            Some(unsafe { Self::from_raw_psid_unchecked(psid) })
        }
    }

    unsafe fn from_raw_psid_unchecked<'psid>(psid: sys::PSID) -> &'psid Self {
        // SAFETY: Userid is just a wrapper around sys::PSID.
        // therefore converting sys::PSID to &Userid is safe.
        unsafe { &*(psid as *const Self) }
    }
}

pub(crate) struct UseridBuf {
    buf: Vec<u8>,
}

impl ops::Deref for UseridBuf {
    type Target = Userid;

    fn deref(&self) -> &Self::Target {
        unsafe { Userid::from_raw_psid_unchecked(self.buf.as_ptr() as sys::PSID) }
    }
}

impl fmt::Display for UseridBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let userid: &Userid = self;

        write!(f, "{}", userid)
    }
}

impl fmt::Debug for UseridBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let userid: &Userid = self;

        write!(f, "{:?}", userid)
    }
}

impl PartialEq for UseridBuf {
    fn eq(&self, other: &Self) -> bool {
        let lhs: &Userid = self;
        let rhs: &Userid = other;

        lhs.eq(rhs)
    }
}

impl PartialEq<Userid> for UseridBuf {
    fn eq(&self, other: &Userid) -> bool {
        self.buf.as_ptr() as sys::PSID == other.as_raw_psid()
    }
}

impl Eq for UseridBuf {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Groupid(Userid);

impl Groupid {
    pub fn try_clone_to_owned(&self) -> Result<GroupidBuf, io::Error> {
        let useridbuf = self.0.try_clone_to_owned()?;

        Ok(GroupidBuf(useridbuf))
    }

    pub fn groupname(&self) -> Result<OsString, Error> {
        self.0.username()
    }
}

impl fmt::Display for Groupid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl GroupidExt for Groupid {
    fn as_raw_psid(&self) -> sys::PSID {
        self.0.as_raw_psid()
    }

    fn from_raw_psid<'psid>(psid: sys::PSID) -> Option<&'psid Self> {
        if psid.is_null() || (unsafe { sys::IsValidSid(psid) } == 0) {
            None
        } else {
            Some(unsafe { Self::from_raw_psid_unchecked(psid) })
        }
    }

    unsafe fn from_raw_psid_unchecked<'psid>(psid: sys::PSID) -> &'psid Self {
        // SAFETY: Groupid is just a wrapper around sys::PSID.
        // therefore converting sys::PSID to &Userid is safe.
        unsafe { &*(psid as *const Self) }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GroupidBuf(UseridBuf);

impl ops::Deref for GroupidBuf {
    type Target = Groupid;

    fn deref(&self) -> &Self::Target {
        unsafe { Groupid::from_raw_psid_unchecked(self.0.as_raw_psid()) }
    }
}

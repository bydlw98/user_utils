//! Windows-specific wrappers around user and group primitives

mod sys;

use super::Error;

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::slice;

use sys::*;

/// A trait to borrow the psid.
pub trait AsPsid {
    /// Borrows the psid.
    fn as_psid(&self) -> BorrowedPsid<'_>;
}

/// A trait to extract the raw psid.
pub trait AsRawPsid {
    /// Extracts the raw psid.
    fn as_raw_psid(&self) -> c::PSID;
}

/// A borrowed psid.
///
/// This has a lifetime parameter to tie it to the lifetime of something that owns the psid.
#[derive(Clone, Copy)]
pub struct BorrowedPsid<'psid> {
    raw_psid: c::PSID,
    _phantom: PhantomData<&'psid OwnedPsid>,
}

impl BorrowedPsid<'_> {
    /// Returns a `BorrowedPsid` holding the given raw psid if
    /// the resource pointed by psid is a valid SID
    ///
    /// # windows_sys functions used
    ///
    /// - [`IsValidSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-isvalidsid)
    pub fn borrow_raw(psid: c::PSID) -> Option<Self> {
        if psid.is_null() || (unsafe { c::IsValidSid(psid) } == 0) {
            None
        } else {
            Some(unsafe { Self::borrow_raw_unchecked(psid) })
        }
    }

    /// Returns a `BorrowedPsid` holding the given raw psid without checking
    /// if the raw psid is valid
    ///
    /// See the safe version, [`borrow_raw`], for more details
    ///
    /// [`borrow_raw`]: BorrowedPsid::borrow_raw
    pub unsafe fn borrow_raw_unchecked(psid: c::PSID) -> Self {
        Self {
            raw_psid: psid,
            _phantom: PhantomData,
        }
    }

    /// Creates a new `OwnedPsid` instance
    ///
    /// # windows_sys functions used
    ///
    /// - [`GetLengthSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getlengthsid)
    /// - [`CopySid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-copysid)
    pub fn try_clone_to_owned(&self) -> Result<OwnedPsid, io::Error> {
        let sid_length = unsafe { c::GetLengthSid(self.raw_psid) };
        let mut buf: Vec<u8> = vec![0; sid_length as usize];
        let return_code =
            unsafe { c::CopySid(sid_length, buf.as_mut_ptr() as c::PSID, self.raw_psid) };

        // On success, return_code is non-zero
        if return_code != 0 {
            Ok(OwnedPsid { buf })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Searches database and returns the account name of SID in a `DOMAIN\name` format
    ///
    /// # windows_sys functions used
    ///
    /// - [`LookupAccountSidW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsidw)
    pub fn lookup_accountname(&self) -> Result<OsString, Error> {
        let mut wide_name_length: u32 = 32;
        let mut wide_domain_length: u32 = 32;
        let mut wide_name_buf: [u16; 32] = [0; 32];
        let mut wide_domain_buf: [u16; 32] = [0; 32];
        let mut sid_name_use = c::SidTypeUnknown;

        let return_code = unsafe {
            c::LookupAccountSidW(
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
            Ok(Self::accountname_from_wide_domain_and_name(
                &wide_domain_buf,
                &wide_name_buf,
            ))
        }
        // If GetLastError() returns ERROR_NONE_MAPPED, means
        // unable to get the name of SID
        else if unsafe { c::GetLastError() } == c::ERROR_NONE_MAPPED {
            Err(Error::NoRecord)
        } else {
            // Retry lookup SID name with correct size
            let mut wide_name = vec![0; wide_name_length as usize];
            let mut wide_domain = vec![0; wide_domain_length as usize];

            let return_code = unsafe {
                c::LookupAccountSidW(
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
                Ok(Self::accountname_from_wide_domain_and_name(
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
    pub fn convert_to_string_sid(&self) -> Result<String, io::Error> {
        let mut wide_cstring_sid = MaybeUninit::<*mut u16>::uninit();
        let return_code =
            unsafe { c::ConvertSidToStringSidW(self.raw_psid, wide_cstring_sid.as_mut_ptr()) };

        // On success, return_code is non-zero
        if return_code != 0 {
            let wide_cstring_sid = unsafe { wide_cstring_sid.assume_init() };
            let wide_cstring_sid_len = unsafe { c::wcslen(wide_cstring_sid) };
            let wide_cstring_sid_slice =
                unsafe { slice::from_raw_parts(wide_cstring_sid, wide_cstring_sid_len) };
            let string_sid = String::from_utf16_lossy(wide_cstring_sid_slice);
            unsafe { c::LocalFree(wide_cstring_sid as c::HLOCAL) };

            Ok(string_sid)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn accountname_from_wide_domain_and_name(
        wide_domain_buf: &[u16],
        wide_name_buf: &[u16],
    ) -> OsString {
        let mut accountname = utf16_until_null_to_osstring(&wide_domain_buf);
        accountname.push("\\");
        accountname.push(utf16_until_null_to_osstring(&wide_name_buf));

        accountname
    }
}

impl fmt::Display for BorrowedPsid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.convert_to_string_sid() {
            Ok(string_sid) => write!(f, "{}", string_sid),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl fmt::Debug for BorrowedPsid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.convert_to_string_sid() {
            Ok(string_sid) => write!(f, "{}", string_sid),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl PartialEq for BorrowedPsid<'_> {
    fn eq(&self, other: &Self) -> bool {
        unsafe { c::EqualSid(self.raw_psid, other.raw_psid) != 0 }
    }
}

impl Eq for BorrowedPsid<'_> {}

impl PartialEq<OwnedPsid> for BorrowedPsid<'_> {
    fn eq(&self, other: &OwnedPsid) -> bool {
        unsafe { c::EqualSid(self.raw_psid, other.as_raw_psid()) != 0 }
    }
}

impl AsPsid for BorrowedPsid<'_> {
    #[inline]
    fn as_psid(&self) -> BorrowedPsid<'_> {
        *self
    }
}

impl AsRawPsid for BorrowedPsid<'_> {
    #[inline]
    fn as_raw_psid(&self) -> c::PSID {
        self.raw_psid
    }
}

/// An owned Psid
pub struct OwnedPsid {
    buf: Vec<u8>,
}

impl OwnedPsid {
    /// Creates a new `OwnedPsid` instance containing the well-known World SID
    ///
    /// # windows_sys functions used
    ///
    /// - [`GetSidLengthRequired`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidlengthrequired)
    /// - [`CreateWellKnownSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createwellknownsid)
    pub fn world() -> Result<Self, io::Error> {
        let mut world_sid_len = unsafe { c::GetSidLengthRequired(1) };
        let mut buf: Vec<u8> = vec![0; world_sid_len as usize];

        let return_code = unsafe {
            c::CreateWellKnownSid(
                c::WinWorldSid,
                ptr::null_mut(),
                buf.as_mut_ptr() as c::PSID,
                &mut world_sid_len,
            )
        };

        // On success, return_code is 0
        if return_code != 0 {
            Ok(Self { buf })
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl fmt::Display for OwnedPsid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let borrowed_psid = self.as_psid();

        match borrowed_psid.convert_to_string_sid() {
            Ok(string_sid) => write!(f, "{}", string_sid),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl fmt::Debug for OwnedPsid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let borrowed_psid = self.as_psid();

        match borrowed_psid.convert_to_string_sid() {
            Ok(string_sid) => write!(f, "{}", string_sid),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl PartialEq for OwnedPsid {
    fn eq(&self, other: &Self) -> bool {
        unsafe { c::EqualSid(self.as_raw_psid(), other.as_raw_psid()) != 0 }
    }
}

impl Eq for OwnedPsid {}

impl PartialEq<BorrowedPsid<'_>> for OwnedPsid {
    fn eq(&self, other: &BorrowedPsid<'_>) -> bool {
        other.eq(self)
    }
}

impl AsPsid for OwnedPsid {
    #[inline]
    fn as_psid(&self) -> BorrowedPsid<'_> {
        unsafe { BorrowedPsid::borrow_raw_unchecked(self.as_raw_psid()) }
    }
}

impl AsRawPsid for OwnedPsid {
    #[inline]
    fn as_raw_psid(&self) -> c::PSID {
        self.buf.as_ptr() as c::PSID
    }
}

fn utf16_until_null_to_osstring(utf16_buf: &[u16]) -> OsString {
    OsString::from_wide(
        &utf16_buf
            .iter()
            .cloned()
            .take_while(|&c| c != 0)
            .collect::<Vec<u16>>(),
    )
}

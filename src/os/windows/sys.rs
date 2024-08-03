use std::ffi::OsString;
use std::fmt;
use std::io;
use std::mem::MaybeUninit;
use std::ptr;
use std::slice;

pub use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_NONE_MAPPED, HLOCAL, PSID,
};
pub use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
pub use windows_sys::Win32::Security::{
    CopySid, CreateWellKnownSid, EqualSid, GetLengthSid, GetSidLengthRequired, IsValidSid,
    LookupAccountSidW, SidTypeUnknown, WinWorldSid,
};

use super::utils;
use crate::Error;

/// Returns a duplicate copy of SID.
///
/// # windows_sys functions used
///
/// - [`GetLengthSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getlengthsid)
/// - [`CopySid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-copysid)
pub fn copy_sid(psid: PSID) -> Result<Vec<u8>, io::Error> {
    let sid_length = unsafe { GetLengthSid(psid) };
    let mut buf: Vec<u8> = vec![0; sid_length as usize];
    let return_code = unsafe { CopySid(sid_length, buf.as_mut_ptr() as PSID, psid) };

    // On success, return_code is non-zero
    if return_code != 0 {
        Ok(buf)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Searches database and returns the account name of SID in a `DOMAIN\name` format
///
/// # windows_sys functions used
///
/// - [`LookupAccountSidW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsidw)
pub fn lookup_account_sid(psid: PSID) -> Result<OsString, Error> {
    let mut wide_name_length: u32 = 32;
    let mut wide_domain_length: u32 = 32;
    let mut wide_name_buf: [u16; 32] = [0; 32];
    let mut wide_domain_buf: [u16; 32] = [0; 32];
    let mut sid_name_use = SidTypeUnknown;

    let return_code = unsafe {
        LookupAccountSidW(
            ptr::null(),
            psid,
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
    else if unsafe { GetLastError() } == ERROR_NONE_MAPPED {
        Err(Error::NoRecord)
    } else {
        // Retry lookup SID name with correct size
        let mut wide_name = vec![0; wide_name_length as usize];
        let mut wide_domain = vec![0; wide_domain_length as usize];

        let return_code = unsafe {
            LookupAccountSidW(
                ptr::null(),
                psid,
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

pub fn fmt_sid(psid: PSID, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match convert_sid_to_string_sid(psid) {
        Ok(string_sid) => write!(f, "{}", string_sid),
        Err(_) => Err(fmt::Error),
    }
}

/// Converts an SID to a displayable string format
///
/// # windows_sys functions used
///
/// - [`ConvertSidToStringSidW`](https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtostringsidw)
pub fn convert_sid_to_string_sid(psid: PSID) -> Result<String, io::Error> {
    let mut wide_cstring_sid = MaybeUninit::<*mut u16>::uninit();
    let return_code = unsafe { ConvertSidToStringSidW(psid, wide_cstring_sid.as_mut_ptr()) };

    // On success, return_code is non-zero
    if return_code != 0 {
        let wide_cstring_sid = unsafe { wide_cstring_sid.assume_init() };
        let wide_cstring_sid_len = unsafe { libc::wcslen(wide_cstring_sid) };
        let wide_cstring_sid_slice =
            unsafe { slice::from_raw_parts(wide_cstring_sid, wide_cstring_sid_len) };
        let string_sid = String::from_utf16_lossy(wide_cstring_sid_slice);
        unsafe { LocalFree(wide_cstring_sid as HLOCAL) };

        Ok(string_sid)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Checks for equality between the 2 SID provided.
///
/// # windows_sys functions used
///
/// - [`EqualSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-equalsid)
pub fn equal_sid(psid_1: PSID, psid_2: PSID) -> bool {
    unsafe { EqualSid(psid_1, psid_2) != 0 }
}

/// Checks whether SID is valid.
///
/// # windows_sys functions used
///
/// - [`IsValidSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-isvalidsid)
pub fn is_invalid_sid(psid: PSID) -> bool {
    psid.is_null() || (unsafe { IsValidSid(psid) } == 0)
}

/// Returns a buffer containing the well-known World SID.
///
/// # windows_sys functions used
///
/// - [`GetSidLengthRequired`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidlengthrequired)
/// - [`CreateWellKnownSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createwellknownsid)
pub fn create_world_sid() -> Result<Vec<u8>, io::Error> {
    let mut world_sid_len = unsafe { GetSidLengthRequired(1) };
    let mut buf: Vec<u8> = vec![0; world_sid_len as usize];

    let return_code = unsafe {
        CreateWellKnownSid(
            WinWorldSid,
            ptr::null_mut(),
            buf.as_mut_ptr() as PSID,
            &mut world_sid_len,
        )
    };

    // On success, return_code is non-zero
    if return_code != 0 {
        Ok(buf)
    } else {
        Err(io::Error::last_os_error())
    }
}

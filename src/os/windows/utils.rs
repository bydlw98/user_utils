use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

pub fn accountname_from_wide_domain_and_name(
    wide_domain_buf: &[u16],
    wide_name_buf: &[u16],
) -> OsString {
    let mut accountname = utf16_until_null_to_osstring(&wide_domain_buf);
    accountname.push("\\");
    accountname.push(utf16_until_null_to_osstring(&wide_name_buf));

    accountname
}

pub fn utf16_until_null_to_osstring(utf16_buf: &[u16]) -> OsString {
    OsString::from_wide(
        &utf16_buf
            .iter()
            .cloned()
            .take_while(|&c| c != 0)
            .collect::<Vec<u16>>(),
    )
}

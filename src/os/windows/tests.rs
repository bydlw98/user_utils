use super::*;

use std::ptr;

#[test]
fn test_groupidext_world() {
    let world_groupid = GroupidBuf::world().unwrap();
    let world_groupid_str = world_groupid.to_string();

    assert_eq!(world_groupid_str, "S-1-1-0");
}

#[test]
fn test_useridext_from_raw_psid_null() {
    let psid: sys::PSID = ptr::null_mut();
    let option = Userid::from_raw_psid(psid);

    assert!(matches!(option, None));
}

#[test]
fn test_groupidext_from_raw_psid_null() {
    let psid: sys::PSID = ptr::null_mut();
    let option = Groupid::from_raw_psid(psid);

    assert!(matches!(option, None));
}

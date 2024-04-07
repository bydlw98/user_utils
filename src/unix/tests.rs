use super::*;

use std::env;
use std::process::Command;

#[test]
fn test_passwd_lookup_by_uid_ok() {
    if let Ok(pwd) = Passwd::lookup_by_uid(unsafe { libc::getuid() }) {
        assert_eq!(pwd.name(), env::var_os("LOGNAME").unwrap());

        assert_eq!(
            pwd.uid(),
            BorrowedUid::borrow_raw(unsafe { libc::getuid() })
        );

        assert_eq!(
            pwd.gid(),
            BorrowedGid::borrow_raw(unsafe { libc::getgid() })
        );

        assert_eq!(pwd.dir(), env::var_os("HOME").unwrap());

        assert_eq!(pwd.shell(), env::var_os("SHELL").unwrap());
    } else {
        panic!();
    }
}

#[test]
fn test_passwd_lookup_by_uid_norecord() {
    let result = Passwd::lookup_by_uid(libc::uid_t::MAX - 3);

    assert!(matches!(result, Err(Error::NoRecord)));
}

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

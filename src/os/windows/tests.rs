use super::*;

#[test]
fn test_groupidext_world() {
    let world_groupid = GroupidBuf::world().unwrap();
    let world_groupid_str = world_groupid.to_string();
    println!("{:?}", world_groupid_str);

    assert_eq!(world_groupid_str, "S-1-1-0");
}

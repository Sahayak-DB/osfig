use winapi::shared::minwindef::BYTE;
use windows_permissions::{LocalBox, Sid};

#[allow(unused)]
pub fn get_cur_sid() -> Vec<BYTE> {
    let cur_user = windows_acl::helper::current_user();
    let cur_sid = windows_acl::helper::name_to_sid(&cur_user.unwrap().to_string(), None);

    cur_sid.unwrap()
}

#[allow(unused)]
pub fn get_cur_username() -> String {
    windows_acl::helper::current_user().unwrap()
}

#[allow(unused)]
pub fn sid_to_username(sid: &String) -> (String, String) {
    // Construct ACL System\Username
    let acl_sid: LocalBox<Sid> = sid.parse().unwrap();
    let result = windows_permissions::wrappers::LookupAccountSid(acl_sid.as_ref()).unwrap();
    let system_name = result.1.to_str().unwrap();
    let user_name = result.0.to_str().unwrap();

    (system_name.to_string(), user_name.to_string())
}

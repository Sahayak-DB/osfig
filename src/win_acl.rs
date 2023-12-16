use crate::helpers;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use winapi::shared::minwindef::BYTE;
#[cfg(windows)]
use {
    winapi::um::winnt,
    windows_acl::acl::{ACLEntry, AceType, ACL},
};

#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
pub struct WinaclEntry {
    pub(crate) acl_type: String,
    pub(crate) acl_flags: String,
    pub(crate) acl_sid: String,
    pub(crate) acl_user: String,
    pub(crate) acl_mask: String,
}
#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
pub struct WinAcl {
    pub(crate) object_type: String,
    pub(crate) acl_entries: Vec<WinaclEntry>,
}

#[cfg(windows)]
pub fn get_win_acls(path: &Path, include_sacl: bool) -> WinAcl {
    if include_sacl {
        debug!("Collecting SACLs");
    } else {
        debug!("Collecting DACLs");
    }

    if File::open(&path).is_err() {
        warn!("Cannot open file: {}", path.to_str().unwrap());
        return WinAcl {
            object_type: "".to_string(),
            acl_entries: vec![],
        };
    }
    let sacl = ACL::from_file_path(path.to_str().unwrap(), include_sacl).unwrap();
    let mut acl_result: WinAcl = WinAcl {
        object_type: "".to_string(),
        acl_entries: vec![],
    };
    acl_result.object_type = sacl.object_type().to_string();
    for item in &sacl.all().unwrap() {
        let acl_entry = read_win_file_acl(&sacl, item);
        acl_result.acl_entries.push(acl_entry);
    }
    acl_result
}

#[cfg(windows)]
pub fn get_win_dacls(path: &Path) -> WinAcl {
    get_win_acls(path, false)
}

#[cfg(windows)]
pub fn get_win_sacls(path: &Path) -> WinAcl {
    get_win_acls(path, true)
}

#[cfg(windows)]
fn read_win_file_acl(acl: &ACL, acl_entry: &ACLEntry) -> WinaclEntry {
    // Some of the code in this function was heavily influenced by example code from the creator
    // of the winnt crate. I strongly encourage you to check it out for your own projects.

    fn build_description(mask: BYTE, definitions: &[(BYTE, &str); 7]) -> String {
        let mut descriptions = definitions
            .iter()
            .filter(|(def_mask, _)| mask & def_mask > 0)
            .map(|(_, desc)| *desc)
            .collect::<Vec<_>>();

        if descriptions.is_empty() {
            descriptions.push("None");
        }

        descriptions.join("|")
    }

    let mut acl_entry_result: WinaclEntry = WinaclEntry {
        acl_type: acl_entry.entry_type.to_string(),
        acl_flags: "".to_string(),
        acl_sid: "".to_string(),
        acl_user: "".to_string(),
        acl_mask: "".to_string(),
    };

    // Check ACL SID
    let sid = match acl_entry.sid {
        Some(ref sid) => windows_acl::helper::sid_to_string((*sid).as_ptr() as winnt::PSID)
            .unwrap_or_else(|_| "Bad SID Format".to_string()),
        None => "None".to_string(),
    };

    // Check ACL Flags
    let defined_flags = [
        (winnt::CONTAINER_INHERIT_ACE, "ContainerInheritAce"),
        (winnt::FAILED_ACCESS_ACE_FLAG, "FailedAccessAce"),
        (winnt::INHERIT_ONLY_ACE, "InheritOnlyAce"),
        (winnt::INHERITED_ACE, "InheritedAce"),
        (winnt::NO_PROPAGATE_INHERIT_ACE, "NoPropagateInheritAce"),
        (winnt::OBJECT_INHERIT_ACE, "ObjectInheritAce"),
        (winnt::SUCCESSFUL_ACCESS_ACE_FLAG, "SuccessfulAccessAce"),
    ];

    acl_entry_result.acl_flags = build_description(acl_entry.flags, &defined_flags);

    let mut masks: Vec<String> = Vec::new();
    if acl_entry.entry_type == AceType::SystemMandatoryLabel {
        let defined_masks = [
            (winnt::SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, "NoExecUp"),
            (winnt::SYSTEM_MANDATORY_LABEL_NO_READ_UP, "NoReadUp"),
            (winnt::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, "NoWriteUp"),
        ];
        for &(mask, desc) in &defined_masks {
            if (acl_entry.mask & mask) > 0 {
                masks.push(desc.to_string());
            }
        }
    } else {
        match acl.object_type() {
            windows_acl::acl::ObjectType::FileObject => {
                if (acl_entry.mask & winnt::FILE_ALL_ACCESS) == winnt::FILE_ALL_ACCESS {
                    masks.push("FileAllAccess".to_string());
                } else {
                    if (acl_entry.mask & winnt::FILE_GENERIC_READ)
                        == (winnt::FILE_GENERIC_READ & !winnt::SYNCHRONIZE)
                    {
                        masks.push("FileGenericRead".to_string());
                    }

                    if (acl_entry.mask & winnt::FILE_GENERIC_WRITE)
                        == (winnt::FILE_GENERIC_WRITE & !winnt::SYNCHRONIZE)
                    {
                        masks.push("FileGenericWrite".to_string());
                    }

                    if (acl_entry.mask & winnt::FILE_GENERIC_EXECUTE)
                        == (winnt::FILE_GENERIC_EXECUTE & !winnt::SYNCHRONIZE)
                    {
                        masks.push("FileGenericExec".to_string());
                    }

                    if masks.len() == 0 {
                        let defined_specific_rights = [
                            (winnt::FILE_WRITE_ATTRIBUTES, "FileWriteAttr"),
                            (winnt::FILE_READ_ATTRIBUTES, "FileReadAttr"),
                            (winnt::FILE_DELETE_CHILD, "FileDeleteChild"),
                            (winnt::FILE_EXECUTE, "FileExecuteOrTraverse"),
                            (winnt::FILE_WRITE_EA, "FileWriteEa"),
                            (winnt::FILE_READ_EA, "FileReadEa"),
                            (winnt::FILE_APPEND_DATA, "FileAppendDataOrAddSubDir"),
                            (winnt::FILE_WRITE_DATA, "FileWriteDataOrAddFile"),
                            (winnt::FILE_READ_DATA, "FileReadDataOrListDir"),
                        ];
                        for &(mask, desc) in &defined_specific_rights {
                            if (acl_entry.mask & mask) > 0 {
                                masks.push(desc.to_string());
                            }
                        }
                    }
                }
            }
            _ => {
                let defined_std_rights = [
                    (winnt::DELETE, "Delete"),
                    (winnt::GENERIC_READ, "GenericRead"),
                    (winnt::GENERIC_WRITE, "GenericWrite"),
                    (winnt::GENERIC_ALL, "GenericAll"),
                    (winnt::GENERIC_EXECUTE, "GenericExec"),
                    (winnt::READ_CONTROL, "ReadControl"),
                    (winnt::WRITE_DAC, "WriteDac"),
                    (winnt::WRITE_OWNER, "WriteOwner"),
                    (winnt::MAXIMUM_ALLOWED, "MaxAllowed"),
                    (winnt::SYNCHRONIZE, "Synchronize"),
                ];
                if (acl_entry.mask & winnt::STANDARD_RIGHTS_ALL) == winnt::STANDARD_RIGHTS_ALL {
                    masks.push("StandardRightsAll".to_string());
                } else {
                    for &(mask, desc) in &defined_std_rights {
                        if (acl_entry.mask & mask) > 0 {
                            masks.push(desc.to_string());
                        }
                    }
                }
            }
        }
    }
    if masks.is_empty() {
        masks.push("None".to_string());
    }
    acl_entry_result.acl_mask = masks.join("|");

    // Construct ACL System\Username
    let (system_name, user_name) = helpers::sid_to_username(&sid);
    acl_entry_result.acl_sid = sid;
    acl_entry_result.acl_user = format!("{}\\{}", system_name, user_name);

    acl_entry_result
}

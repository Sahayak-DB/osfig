use crate::win_helpers;
use serde::{Deserialize, Serialize};
use std::path::Path;
use winapi::um::winnt;
use windows_acl::acl::{ACLEntry, AceType, ACL};

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

pub fn get_dacls(path: &Path) -> WinAcl {
    let dacl = windows_acl::acl::ACL::from_file_path(path.to_str().unwrap(), false).unwrap();
    let mut acl_result: WinAcl = WinAcl {
        object_type: "".to_string(),
        acl_entries: vec![],
    };
    acl_result.object_type = dacl.object_type().to_string();
    for item in &dacl.all().unwrap() {
        let acl_entry = read_win_file_acl(&dacl, item);
        acl_result.acl_entries.push(acl_entry);
    }
    acl_result
}

pub fn get_sacls(path: &Path) -> WinAcl {
    let dacl = windows_acl::acl::ACL::from_file_path(path.to_str().unwrap(), true).unwrap();
    let mut acl_result: WinAcl = WinAcl {
        object_type: "".to_string(),
        acl_entries: vec![],
    };
    acl_result.object_type = dacl.object_type().to_string();
    for item in &dacl.all().unwrap() {
        let acl_entry = read_win_file_acl(&dacl, item);
        acl_result.acl_entries.push(acl_entry);
    }
    acl_result
}

fn read_win_file_acl(acl: &ACL, acl_entry: &ACLEntry) -> WinaclEntry {
    // Some of the code in this function was heavily influenced by example code from the creator
    // of the winnt crate. I strongly encourage you to check it out for your own projects.
    let mut acl_entry_result: WinaclEntry = WinaclEntry {
        acl_type: "".to_string(),
        acl_flags: "".to_string(),
        acl_sid: "".to_string(),
        acl_user: "".to_string(),
        acl_mask: "".to_string(),
    };
    acl_entry_result.acl_type = acl_entry.entry_type.to_string();

    // Check ACL SID
    let sid = match acl_entry.sid {
        Some(ref sid) => windows_acl::helper::sid_to_string((*sid).as_ptr() as winnt::PSID)
            .unwrap_or_else(|_| "Bad SID Format".to_string()),
        None => "None".to_string(),
    };

    // Check ACL Flags
    let mut flags: String = String::new();
    let defined_flags = [
        (winnt::CONTAINER_INHERIT_ACE, "ContainerInheritAce"),
        (winnt::FAILED_ACCESS_ACE_FLAG, "FailedAccessAce"),
        (winnt::INHERIT_ONLY_ACE, "InheritOnlyAce"),
        (winnt::INHERITED_ACE, "InheritedAce"),
        (winnt::NO_PROPAGATE_INHERIT_ACE, "NoPropagateInheritAce"),
        (winnt::OBJECT_INHERIT_ACE, "ObjectInheritAce"),
        (winnt::SUCCESSFUL_ACCESS_ACE_FLAG, "SuccessfulAccessAce"),
    ];

    for &(flag, desc) in &defined_flags {
        if (acl_entry.flags & flag) > 0 {
            if flags.len() > 0 {
                flags += "|";
            }
            flags += desc;
        }
    }
    if flags.len() == 0 {
        flags += "None";
    }
    acl_entry_result.acl_flags = flags;

    let mut masks: String = String::new();
    if acl_entry.entry_type == AceType::SystemMandatoryLabel {
        let defined_masks = [
            (winnt::SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, "NoExecUp"),
            (winnt::SYSTEM_MANDATORY_LABEL_NO_READ_UP, "NoReadUp"),
            (winnt::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, "NoWriteUp"),
        ];
        for &(mask, desc) in &defined_masks {
            if (acl_entry.mask & mask) > 0 {
                if masks.len() > 0 {
                    masks += "|";
                }
                masks += desc;
            }
        }
    } else {
        match acl.object_type() {
            windows_acl::acl::ObjectType::FileObject => {
                if (acl_entry.mask & winnt::FILE_ALL_ACCESS) == winnt::FILE_ALL_ACCESS {
                    if masks.len() > 0 {
                        masks += "|";
                    }
                    masks += "FileAllAccess";
                } else {
                    if (acl_entry.mask & winnt::FILE_GENERIC_READ)
                        == (winnt::FILE_GENERIC_READ & !winnt::SYNCHRONIZE)
                    {
                        if masks.len() > 0 {
                            masks += "|";
                        }
                        masks += "FileGenericRead";
                    }

                    if (acl_entry.mask & winnt::FILE_GENERIC_WRITE)
                        == (winnt::FILE_GENERIC_WRITE & !winnt::SYNCHRONIZE)
                    {
                        if masks.len() > 0 {
                            masks += "|";
                        }
                        masks += "FileGenericWrite";
                    }

                    if (acl_entry.mask & winnt::FILE_GENERIC_EXECUTE)
                        == (winnt::FILE_GENERIC_EXECUTE & !winnt::SYNCHRONIZE)
                    {
                        if masks.len() > 0 {
                            masks += "|";
                        }
                        masks += "FileGenericExec";
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
                                if masks.len() > 0 {
                                    masks += "|";
                                }
                                masks += desc;
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
                    masks += "StandardRightsAll";
                } else {
                    for &(mask, desc) in &defined_std_rights {
                        if (acl_entry.mask & mask) > 0 {
                            if masks.len() > 0 {
                                masks += "|";
                            }
                            masks += desc;
                        }
                    }
                }
            }
        }
    }
    if masks.len() == 0 {
        masks += "None";
    }
    acl_entry_result.acl_mask = masks;

    // Construct ACL System\Username
    let (system_name, user_name) = win_helpers::sid_to_username(&sid);
    acl_entry_result.acl_sid = sid;
    acl_entry_result.acl_user = format!("{}\\{}", system_name, user_name);

    acl_entry_result
}

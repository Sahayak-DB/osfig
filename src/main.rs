use chrono::{DateTime};
use log::info;
use filetime;
use filetime::FileTime;
use std::fs;
use std::any::Any;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::os::windows::fs::MetadataExt;
use is_elevated::is_elevated;
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg;
use std::env::args;

use crate::win_acl::{get_dacls, get_sacls};
use crate::win_helpers::get_cur_username;

mod hashing;
mod osfig_state;
mod logging;
mod win_acl;
mod win_helpers;


fn main() -> std::io::Result<()> {
    logging::setup_logging();
    info!("Logging setup completed");
    info!("Initializing OSFIG");

    // Todo Find some nifty ASCII art for this. User preferences be damned, I love the ascii
    crate::osfig_state::print_usage();

    // Testing file hashing
    // Grab args, drop the 0th, and boogie
    let mut options: Vec<String> = args().collect();
    options.remove(0);
    let mut path = Path::new("./test");
    if options.len() == 1 {
        path = Path::new(options.get(0).unwrap());
    }
    println!("Using this Path: {:?}", path);

    // Testing file hashes
    let hashes = crate::hashing::get_all_hashes(path);
    println!("     MD5: {}", hashes.md5);
    println!("  SHA256: {}", hashes.sha256);
    println!(" BLAKE2S: {}\n", hashes.blake2s);

    // Testing file metadata
    let md = fs::metadata(path).unwrap();
    // File Creation
    let file_time = FileTime::from_creation_time(&md);
    let created_time = DateTime::from_timestamp(file_time.unwrap().unix_seconds(), file_time.unwrap().nanoseconds());
    println!(" Created: {}", created_time.unwrap().to_string());
    // File Modified
    let file_time = FileTime::from_last_modification_time(&md);
    let mod_time = DateTime::from_timestamp(file_time.unix_seconds(), file_time.nanoseconds());
    println!("Modified: {}\n", mod_time.unwrap().to_string());
    // File Access
    // Todo research how to avoid update atime when reading file in Windows
    // Deprecating for now as this is just useless
    // let file_time = FileTime::from_last_access_time(&md);
    // let acc_time = DateTime::from_timestamp(file_time.unix_seconds(), file_time.nanoseconds());
    // println!("Accessed: {:?}", acc_time.unwrap());

    // Testing file attributes
    println!("{:?}", path.canonicalize().unwrap().to_str().unwrap());
    println!("Stem: {:?}", path.file_stem());
    println!("RelPath: {:?}", path.to_str().unwrap());
    println!("Rel Parent: {:?}", path.parent().unwrap().to_str().unwrap());
    println!("Name: {:?}", path.file_name().unwrap());
    let md = fs::metadata(path).unwrap();
    let is_dir = md.is_dir();
    println!("dir?: {}", is_dir);
    let is_file = md.is_file();
    println!("file?: {}", is_file);
    let is_sym = md.is_symlink();
    println!("Symlnk: {}", is_sym);
    let is_ro = md.permissions().readonly();
    println!("ReadOnly: {}", is_ro);
    let file_perms = md.permissions();
    println!("Perms: {:?}", file_perms);
    let file_type = md.file_type();
    println!("Type: {:?}", file_type);
    let file_type_id = file_type.type_id();
    println!("Type ID: {:?}", file_type_id);
    println!("Type ID 2: {:?}", file_type_id.type_id());
    let file_sz = md.file_size();
    println!("Size: {}", file_sz);
    let file_attrs = md.file_attributes();
    println!("Attrs: {}\n", file_attrs);

    // Testing flat file
    let utf8_contents: String;
    if File::open(path).is_err() {
        info!("Cannot open file: {:?}", path.to_str());
        utf8_contents = String::from("Cannot open file.");
    }
    else {
        // Todo Consider using crate simdutf8 in the future for performance enhancements
        let mut myfile = File::open(path).unwrap();
        let mut file_contents: Vec<u8> = Vec::new();
        myfile.read_to_end(&mut file_contents).expect("Not a valid UTF8 file.");
        utf8_contents = match std::str::from_utf8(file_contents.as_slice()) {
            Ok(contents) => contents,
            Err(_e) => "Unable to parse file."
        }.parse().unwrap();
    }
    println!("Contents: {}\n", utf8_contents);

    // Testing ACLs
    // Discretionary ACL
    let dacl_result = get_dacls(path);
    println!("DACLs: {:?}\n", dacl_result);

    // Print a formatted version of the DACL entries
    // println!("DACL Object Type: {}, Entries: {}", dacl_result.object_type.to_string(), dacl_result.acl_entries.len());
    // for entry in dacl_result.acl_entries {
    //     println!("AccessControlEntry {{Type={},Flags={},Sid={},User={},Mask={}}}",
    //              entry.acl_type,
    //              entry.acl_flags,
    //              entry.acl_sid,
    //              entry.acl_user,
    //              entry.acl_mask
    //     );
    // }
    // println!();

    // System ACL
    // This requires Administrator privileges
    if is_elevated() {
        let sacl_result = get_sacls(path);
        println!("SACLs: {:?}", sacl_result);

        // Print a formatted version of the DACL entries
        println!("SACL Object Type: {}, Entries: {}", sacl_result.object_type.to_string(), sacl_result.acl_entries.len());
        for entry in sacl_result.acl_entries {
            println!("AccessControlEntry {{Type={},Flags={},Sid={},User={},Mask={}}}",
                     entry.acl_type,
                     entry.acl_flags,
                     entry.acl_sid,
                     entry.acl_user,
                     entry.acl_mask
            );
        }
        println!();
    }



    // Testing Registry Browsing
    let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    println!("hklm: {:?}", hklm);
    let reg_handle = hklm.open_subkey("SOFTWARE").unwrap();
    println!("reg_handle: {:?}", reg_handle);
    let reg_handle = reg_handle.open_subkey("Python").unwrap();
    println!("reg_handle: {:?}", reg_handle);
    let reg_handle = reg_handle.open_subkey("PythonCore").unwrap();
    println!("reg_handle: {:?}", reg_handle);
    let reg_value:String = reg_handle.get_value("DisplayName").unwrap();
    println!("reg_values: {:?}", reg_value);

    // Testing Registry Direct Paths
    let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    let reg_handle = hklm.open_subkey("SOFTWARE\\Python\\PythonCore").unwrap();
    let reg_value:String = reg_handle.get_value("DisplayName").unwrap();
    println!("reg_value: {:?}", reg_value);

    println!("Current Running User: {}", get_cur_username());
    println!("Current User Sid: {:?}", win_helpers::get_cur_sid());


    Ok(())
}

// Todo Configuration file for runtime directions
// Todo Singular output in json
// Todo Store scans in local db for comparisons
// Todo Show only changed files in output
// Todo Show all results in ultra-verbose mode
// Todo Show contents diffs in verbose mode
// Todo Set up a build pipeline that automatically addresses versioning
// Todo Add commandline options
// Todo check out the winapi crate

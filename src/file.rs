use crate::hashing;
use chrono::DateTime;
use chrono::Utc;
use filetime::FileTime;
use glob::{glob, GlobResult};
use is_elevated::is_elevated;
use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
use std::fs::File;
use std::io::{BufWriter, Read};
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::win_acl::{get_dacls, get_sacls, WinAcl};

#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
pub struct FileScanResult {
    pub(crate) scantime: String,
    pub(crate) path: Box<PathBuf>,
    name: String,
    pub(crate) is_dir: bool,
    pub(crate) is_file: bool,
    pub(crate) is_sym: bool,
    pub(crate) is_readonly: bool,
    pub(crate) exists: bool,
    pub(crate) md5: String,
    pub(crate) sha256: String,
    pub(crate) blake2s: String,
    pub(crate) ctime: String,
    pub(crate) mtime: String,
    pub(crate) atime: String,
    pub(crate) size: u64,
    pub(crate) attrs: u32,
    pub(crate) contents: String,
    pub(crate) dacl: WinAcl,
    pub(crate) sacl: WinAcl,
}

fn store_json(results: &Vec<FileScanResult>) {
    // Testing storage to json file
    // Todo refactor later for more organized storage of results -- Should this even live here? Plan!
    let results_path = format!(
        "./scans/results-{}.json",
        DateTime::<Utc>::from(SystemTime::now()).timestamp()
    );
    let scans_dir = Path::new(&results_path).parent().unwrap();
    if !scans_dir.exists() {
        match std::fs::create_dir_all(scans_dir) {
            Ok(_) => {
                info!("Created ./scans/ directory")
            }
            Err(e) => {
                error!("Cannot create results directory: {}", e)
            }
        };
    }

    let json_file = File::create(&results_path).unwrap();
    let file_writer = BufWriter::new(json_file);
    let storage_result = serde_json::to_writer_pretty(file_writer, &results);
    match storage_result {
        Ok(_) => {
            info!("Results saved to file {}", &results_path)
        }
        Err(e) => {
            error!("Error writing JSON: {}", e)
        }
    }
}

pub fn scan_files(pattern: &str) -> Vec<FileScanResult> {
    let mut results: Vec<FileScanResult> = Vec::new();
    if glob(pattern).iter().len() >= 1 {
        for entry in glob(pattern).expect("Invalid glob pattern") {
            // Todo add a glob based negation pattern and check if path is not in the anti-pattern matches
            // Todo check default paths in Windows which are typically inaccessible and put them in a default group of ignored dirs: C:\Users\Default User\*
            results.push(scan_file(&entry))
        }
    } else {
        return Vec::new();
    }
    store_json(&results);

    results
}

pub fn scan_file(glob_match: &GlobResult) -> FileScanResult {
    let path = match glob_match.as_ref() {
        Ok(path) => path,
        Err(e) => {
            error!("Glob Error: {}", e);
            Path::new("../test files/test")
        }
    };

    let path_result = Path::new(path);
    if !path_result.exists() {
        let filescanresult: FileScanResult = FileScanResult {
            scantime: DateTime::<Utc>::from(SystemTime::now()).to_string(),
            path: Box::new(PathBuf::from(path)),
            name: "".to_string(),
            is_dir: false,
            is_file: false,
            is_sym: false,
            is_readonly: false,
            exists: false,
            md5: "".to_string(),
            sha256: "".to_string(),
            blake2s: "".to_string(),
            ctime: DateTime::<Utc>::default().to_string(),
            mtime: DateTime::<Utc>::default().to_string(),
            atime: DateTime::<Utc>::default().to_string(),
            size: 0,
            attrs: 0,
            contents: "".to_string(),
            dacl: WinAcl {
                object_type: "".to_string(),
                acl_entries: vec![],
            },
            sacl: WinAcl {
                object_type: "".to_string(),
                acl_entries: vec![],
            },
        };

        return filescanresult;
    }

    let hashes = hashing::get_all_hashes(path);
    let md = fs::metadata(path).unwrap();

    let file_time = FileTime::from_creation_time(&md);
    let created_time = DateTime::from_timestamp(
        file_time.unwrap().unix_seconds(),
        file_time.unwrap().nanoseconds(),
    );

    let file_time = FileTime::from_last_modification_time(&md);
    let mod_time = DateTime::from_timestamp(file_time.unix_seconds(), file_time.nanoseconds());

    // Todo research how to avoid update atime when reading file in Windows
    // let file_time = FileTime::from_last_access_time(&md);
    // let acc_time = DateTime::from_timestamp(file_time.unix_seconds(), file_time.nanoseconds());

    // File contents
    let utf8_contents: String;
    if File::open(path).is_err() {
        info!("Cannot open file: {:?}", path.to_str());
        utf8_contents = String::from("Cannot open file");
    } else {
        // Todo Consider using crate simdutf8 in the future for performance enhancements
        let mut myfile = File::open(path).unwrap();
        let mut file_contents: Vec<u8> = Vec::new();
        myfile
            .read_to_end(&mut file_contents)
            .expect("Not valid UTF8");
        utf8_contents = match std::str::from_utf8(file_contents.as_slice()) {
            Ok(contents) => contents,
            Err(_e) => "Not valid UTF8",
        }
        .parse()
        .unwrap();
    }

    let mut filescanresult: FileScanResult = FileScanResult {
        scantime: DateTime::<Utc>::from(SystemTime::now()).to_string(),
        path: Box::new(path.canonicalize().unwrap().to_owned()),
        name: "".to_string(),
        is_dir: md.is_dir(),
        is_file: md.is_file(),
        is_sym: md.is_symlink(),
        is_readonly: md.permissions().readonly(),
        exists: md.is_file() || md.is_dir(),
        md5: hashes.md5.to_owned(),
        sha256: hashes.sha256.to_owned(),
        blake2s: hashes.blake2s.to_owned(),
        ctime: created_time.unwrap().to_string(),
        mtime: mod_time.unwrap().to_string(),
        atime: DateTime::<Utc>::default().to_string(),
        size: md.file_size(),
        attrs: md.file_attributes(),
        contents: utf8_contents,
        dacl: get_dacls(path),
        sacl: WinAcl {
            object_type: "".to_string(),
            acl_entries: vec![],
        },
    };

    if is_elevated() {
        filescanresult.sacl = get_sacls(path);
    }

    filescanresult
}

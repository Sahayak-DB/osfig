use crate::hashing;
use chrono::DateTime;
use chrono::Utc;
use filetime::FileTime;
use glob::{glob, GlobResult};
use is_elevated::is_elevated;
use log::{debug, error, info, warn};
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
    pub(crate) name: String,
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
        "./scans/latest/results-{}.json",
        DateTime::<Utc>::from(SystemTime::now()).timestamp()
    );
    let scans_dir = Path::new(&results_path).parent().unwrap();
    if !scans_dir.exists() {
        match fs::create_dir_all(scans_dir) {
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
    info!("Using file pattern: {}", pattern);
    let mut results: Vec<FileScanResult> = Vec::new();
    // Validate there is no PatternError being returned. Fail fast if so by creating a new glob
    // match that will be empty.
    let glob_match = match glob(pattern) {
        Ok(paths) => {
            info!("Valid glob pattern - Checking file results");
            paths
        }
        Err(e) => {
            error!("Invalid Glob Pattern: Error: {}", e);
            glob("").unwrap()
        }
    };

    // Validate if a GlobError occurs on any found path. These are usually permissions/access errors
    // in the OS since we retrieved them from our Paths result returned by glob::glob.
    for entry in glob_match.into_iter() {
        match entry {
            Ok(_) => {}
            Err(e) => {
                warn!("Glob Error: {}", e);
                continue;
            }
        }
        // Todo add a glob based negation pattern and check if path is not in the anti-pattern matches
        results.push(scan_file(&entry))
    }
    // I'm torn on this and may change it later. If the results are 0 it just saved "[]" into the
    // json. Currently we're skipping the save operation and putting a message in the log. For
    // integrity purposes, it may be valuable to store the empty json result instead. Will need to
    // reconsider this later.
    if results.len() == 0 {
        warn!("Found no file results. Validate scan settings, access/permissions, and errors in the log");
    }
    if results.len() > 0 {
        store_json(&results);
    }
    results
}

pub fn scan_file(glob_match: &GlobResult) -> FileScanResult {
    let path = match glob_match.as_ref() {
        Ok(path) => path,
        Err(e) => {
            // Todo validate no further errors can come up. Check TOCTOU cases.
            error!("Contact Developer! - Error: {}", e);
            Path::new("")
        }
    };

    let path_result = Path::new(path);
    // This handles the TOCTOU case where a path exists during glob validation, but not once we
    // are scanning. The glob matching ensures we only have real paths to scan. If it's gone by
    // this time, it's likely to be an ephemeral file and not one we would have wanted results
    // about anyway.
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

    // At this point, we have a living result for a path. Collect the associated data.
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
        // Collect file contents but intentionally fail on non-UTF8 content. There's no value in
        // storing content from other-encoded files.
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

    let dacl_result = get_dacls(path);

    let mut sacl_result = WinAcl {
        object_type: "".to_string(),
        acl_entries: vec![],
    };
    if is_elevated() {
        sacl_result = get_sacls(path);
    }
    let canonical_path = format!("{:?}", &path.canonicalize().unwrap().to_str().unwrap());
    debug!("File scan results complete: {}", canonical_path);

    // We have our scan data--save into the FileScanResult. Note that I have intentionally placed
    // the scantime value as now() instead of when we first checked the file. It takes only a few
    // microseconds to collect data, but could take seconds to collect content on a larger file.
    // For compliance/audit purposes, it's valuable to ascertain when the result was stored, not
    // when the scan started. Since results aren't available until the scan is "done", we are
    // using this moment to declare the scan as "done" and store the results with this timestamp.
    let filescanresult: FileScanResult = FileScanResult {
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
        dacl: dacl_result,
        sacl: sacl_result,
    };

    filescanresult
}
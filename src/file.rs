use crate::hashing;
use crate::osfig_state::OsfigSettings;
use chrono::DateTime;
use chrono::Utc;
use filetime::FileTime;
use glob::{glob, GlobResult};
use log::{debug, error, info, trace, warn};
use prettydiff::diff_lines;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::from_str;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufWriter, Read};
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::time::SystemTime;
use std::{fs, thread, time};

#[cfg(windows)]
use {
    crate::win_acl::{get_win_dacls, get_win_sacls, WinAcl},
    is_elevated::is_elevated,
    std::os::windows::fs::MetadataExt,
};
#[cfg(target_os = "linux")]
use {std::os::unix::fs::MetadataExt, std::os::unix::fs::PermissionsExt};

use crate::scan_settings::FileScanSetting;

#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
pub struct FileScanResult {
    pub(crate) scantime: String,
    pub(crate) path: Box<PathBuf>,
    pub(crate) is_dir: bool,
    pub(crate) is_file: bool,
    pub(crate) is_symbolic_link: bool,
    pub(crate) is_readonly: bool,
    pub(crate) exists: bool,
    pub(crate) md5: String,
    pub(crate) sha256: String,
    pub(crate) blake2s: String,
    pub(crate) creation_time: String,
    pub(crate) modified_time: String,
    pub(crate) access_time: String,
    pub(crate) size: u64,
    pub(crate) attributes: u32,
    pub(crate) contents: String,
    pub(crate) is_modified: bool,
    pub(crate) content_diff: String,
    pub(crate) content_diff_readable: String,
    #[cfg(windows)]
    pub(crate) discretionary_acl: WinAcl,
    #[cfg(windows)]
    pub(crate) system_acl: WinAcl,
}

impl FileScanResult {
    fn default_time() -> String {
        DateTime::<Utc>::default().to_string()
    }

    fn default_path() -> Box<PathBuf> {
        Box::new(PathBuf::from(Path::new("")))
    }
    #[cfg(windows)]
    fn default_acl() -> WinAcl {
        WinAcl {
            object_type: "".to_string(),
            acl_entries: vec![],
        }
    }
}

#[cfg(windows)]
impl Default for FileScanResult {
    fn default() -> Self {
        Self {
            scantime: Self::default_time(),
            path: Self::default_path(),
            is_dir: false,
            is_file: false,
            is_symbolic_link: false,
            is_readonly: false,
            exists: false,
            md5: "".to_string(),
            sha256: "".to_string(),
            blake2s: "".to_string(),
            creation_time: Self::default_time(),
            modified_time: Self::default_time(),
            access_time: Self::default_time(),
            size: 0,
            attributes: 0,
            contents: "".to_string(),
            is_modified: false,
            content_diff: "".to_string(),
            content_diff_readable: "".to_string(),
            discretionary_acl: Self::default_acl(),
            system_acl: Self::default_acl(),
        }
    }
}
#[cfg(target_os = "linux")]
impl Default for FileScanResult {
    fn default() -> Self {
        Self {
            scantime: Self::default_time(),
            path: Self::default_path(),
            is_dir: false,
            is_file: false,
            is_symbolic_link: false,
            is_readonly: false,
            exists: false,
            md5: "".to_string(),
            sha256: "".to_string(),
            blake2s: "".to_string(),
            creation_time: Self::default_time(),
            modified_time: Self::default_time(),
            access_time: Self::default_time(),
            size: 0,
            attributes: 0,
            contents: "".to_string(),
            is_modified: false,
            content_diff: "".to_string(),
            content_diff_readable: "".to_string(),
        }
    }
}

impl FileScanResult {
    #[allow(unused)]
    pub(crate) fn set_path<T: AsRef<Path>>(&mut self, new_path: T) {
        self.path = Box::new(PathBuf::from(new_path.as_ref()))
    }
}

pub fn store_json(results: &Vec<FileScanResult>, path: &str) -> Result<(), std::io::Error> {
    let scans_dir = Path::new(&path).parent().unwrap_or(Path::new("./scans/"));

    if !scans_dir.exists() {
        match fs::create_dir_all(scans_dir) {
            Ok(_) => {
                info!("Created directory: {:?}", scans_dir)
            }
            Err(e) => {
                error!("Cannot create results directory: {}", e)
            }
        };
    }

    let json_file = File::create(&path)?;
    let file_writer = BufWriter::new(json_file);
    let save_result = match serde_json::to_writer_pretty(file_writer, &results) {
        Ok(_) => {}
        Err(_) => {}
    };
    Ok(save_result)
}

pub fn find_newest_file(saved_scans_dir: &str) -> Box<PathBuf> {
    let mut newest_path = PathBuf::new();
    let mut newest_timestamp = DateTime::<Utc>::from_timestamp(0i64, 0u32);

    for mut result_match in glob(saved_scans_dir).unwrap() {
        if !result_match.as_mut().unwrap().exists() {
            continue;
        }
        if result_match.as_mut().unwrap().is_dir() {
            continue;
        }

        #[cfg(windows)]
        let win_time_raw =
            FileTime::from_creation_time(&result_match.as_mut().unwrap().metadata().unwrap())
                .unwrap();
        #[cfg(windows)]
        let this_match_time =
            DateTime::from_timestamp(win_time_raw.unix_seconds(), win_time_raw.nanoseconds());
        #[cfg(target_os = "linux")]
        let this_match_time = DateTime::from_timestamp(
            result_match.as_mut().unwrap().metadata().unwrap().ctime(),
            0,
        );

        if this_match_time > newest_timestamp {
            newest_timestamp = this_match_time;
            newest_path = result_match.unwrap().to_path_buf();
        }
    }

    Box::new(newest_path)
}

pub fn get_latest_results(osfig_settings: &OsfigSettings) -> Vec<FileScanResult> {
    let modified_scan_result_path = format!("{}/*.json", osfig_settings.scan_result_path.as_str());
    let results_path = find_newest_file(modified_scan_result_path.as_str());
    if !results_path.exists() & !results_path.is_file() {
        return Vec::new();
    }

    // Attempt to load latest results from json
    let mut results_file = File::open(results_path.to_str().unwrap()).expect("Cannot open file");

    let mut data: String = "".to_string();
    match results_file.read_to_string(&mut data) {
        Ok(_) => {}
        Err(_) => {
            error!("Unable to read results file. Aborting!");
            error!(
                "Troubleshooting: Validate OSFIG has permissions to read file: {}",
                results_path.to_str().unwrap()
            );
            exit(1);
        }
    };

    let latest_results = match from_str(data.as_ref()) {
        Ok(json_data) => json_data,
        Err(e) => {
            error!("Encountered error reading prior results: Error: {}", e);
            return Vec::new();
        }
    };

    return latest_results;
}

pub fn scan_files(osfig_settings: &OsfigSettings) -> Vec<FileScanResult> {
    let last_scan_results = get_latest_results(&osfig_settings);

    let file_scan_settings = &osfig_settings.scan_settings.file_scan_settings;
    let mut results: Vec<FileScanResult> = Vec::new();

    for file_scan_setting in file_scan_settings {
        let patterns: &Vec<String> = &file_scan_setting.file_patterns;
        info!("Using file pattern: {:?}", patterns);

        for pattern in patterns {
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
                let mut skip_entry = false;
                for negate_pattern in &file_scan_setting.file_ignore_patterns {
                    let glob_negate_matches = match glob(negate_pattern) {
                        Ok(paths) => {
                            debug!("Valid glob ignore pattern - Checking file results");
                            paths
                        }
                        Err(e) => {
                            warn!("Invalid Glob Ignore Pattern: Error: {}", e);
                            glob("").unwrap()
                        }
                    };
                    for negation in glob_negate_matches.into_iter() {
                        match negation {
                            Ok(_) => {
                                if entry.as_ref().unwrap().eq(&negation.unwrap()) {
                                    skip_entry = true;
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Glob Error: {}", e);
                                continue;
                            }
                        }
                    }
                    if skip_entry {
                        break;
                    }
                }
                // We matched our entry to an expanded ignore glob pattern, so skip to next entry.
                if skip_entry {
                    debug!(
                        "Skipping entry due to Ignore Path configuration: {}",
                        entry.as_ref().unwrap().to_str().unwrap()
                    );
                    continue;
                }

                results.push(scan_file(&file_scan_setting, &entry, &last_scan_results));

                // This is quick and dirty for testing, but quite effective at reducing CPU and Disk
                // utilization figures. I may keep it for awhile given the simplicity to implement and
                // how predictable it is in execution for a less knowledgeable end user. It is, after
                // all, deterministic, albeit crude.
                debug!("Sleeping thread before next scan");
                let delay_millis = time::Duration::from_millis(
                    u64::from(osfig_settings.scan_settings.file_scan_delay).clone(),
                );
                thread::sleep(delay_millis);
            }
        }
    }

    // I'm torn on this and may change it later. If the results are 0 it just saved "[]" into the
    // json. Currently we're skipping the save operation and putting a message in the log. For
    // integrity purposes, it may be valuable to store the empty json result instead. Will need to
    // reconsider this later.
    if results.len() == 0 {
        warn!("Found no file results. Validate scan settings, access/permissions, and errors in the log");
    }
    if results.len() > 0 {
        // Todo handle return value and check for errors
        let save_path = format!(
            "{}/results-{}.json",
            osfig_settings.scan_result_path.as_str(),
            DateTime::<Utc>::from(SystemTime::now()).timestamp()
        );
        let save_result = store_json(&results, &save_path);
        match save_result {
            Ok(_) => {
                info!("Results saved to file {}", &save_path)
            }
            Err(e) => {
                error!("Error writing JSON: {}", e)
            }
        }
    }
    results
}

pub fn scan_file(
    settings: &FileScanSetting,
    glob_match: &GlobResult,
    last_scan: &Vec<FileScanResult>,
) -> FileScanResult {
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
        let mut filescanresult: FileScanResult = FileScanResult::default();
        filescanresult.set_path(path);

        return filescanresult;
    }

    // At this point, we have a living result for a path. Collect the associated data.
    debug!("File path confirmed: Collecting hashes");
    let hashes =
        hashing::get_all_hashes(&settings.file_hashes, settings.file_read_buffer_size, path);

    debug!("Collecting metadata");
    let md = fs::metadata(path).unwrap();

    debug!("Collecting timestamps");
    #[cfg(windows)]
    let file_time = FileTime::from_creation_time(&md);
    #[cfg(windows)]
    let created_time = DateTime::from_timestamp(
        file_time.unwrap().unix_seconds(),
        file_time.unwrap().nanoseconds(),
    );
    #[cfg(target_os = "linux")]
    let created_time = DateTime::from_timestamp(md.ctime(), 0);

    let file_time = FileTime::from_last_modification_time(&md);
    let mod_time = DateTime::from_timestamp(file_time.unix_seconds(), file_time.nanoseconds());

    // Todo research how to avoid update access_time when reading file in Windows
    trace!("access_time not yet implemented");
    // let file_time = FileTime::from_last_access_time(&md);
    // let acc_time = DateTime::from_timestamp(file_time.unix_seconds(), file_time.nanoseconds());

    // File contents
    let mut utf8_contents: String = "".to_string();
    if path.is_file() {
        if settings.file_content {
            debug!("Collecting file contents");
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
        }
    }

    #[cfg(windows)]
    let mut dacl_result = WinAcl {
        object_type: "".to_string(),
        acl_entries: vec![],
    };
    #[cfg(windows)]
    if settings.file_dacl {
        dacl_result = get_win_dacls(path);
    }
    #[cfg(windows)]
    let mut sacl_result = WinAcl {
        object_type: "".to_string(),
        acl_entries: vec![],
    };
    #[cfg(windows)]
    if is_elevated() {
        if settings.file_sacl {
            sacl_result = get_win_sacls(path);
        }
    }

    debug!(
        "File scan results complete: {}",
        format!("{:?}", &path.to_str().unwrap())
    );

    // We have our scan data--save into the FileScanResult. Note that I have intentionally placed
    // the scantime value as now() instead of when we first checked the file. It takes only a few
    // microseconds to collect data, but could take seconds to collect content on a larger file.
    // For compliance/audit purposes, it's valuable to ascertain when the result was stored, not
    // when the scan started. Since results aren't available until the scan is "done", we are
    // using this moment to declare the scan as "done" and store the results with this timestamp.
    debug!("Creating FileScanresult");
    let mut filescanresult: FileScanResult = FileScanResult {
        scantime: DateTime::<Utc>::from(SystemTime::now()).to_string(),
        path: Box::new(path.to_path_buf()),
        is_dir: md.is_dir(),
        is_file: md.is_file(),
        is_symbolic_link: md.is_symlink(),
        is_readonly: md.permissions().readonly(),
        exists: md.is_file() || md.is_dir(),
        md5: hashes.md5.to_owned(),
        sha256: hashes.sha256.to_owned(),
        blake2s: hashes.blake2s.to_owned(),
        creation_time: created_time.unwrap().to_string(),
        modified_time: mod_time.unwrap().to_string(),
        access_time: DateTime::<Utc>::default().to_string(),
        #[cfg(windows)]
        size: md.file_size(),
        #[cfg(target_os = "linux")]
        size: md.size(),
        #[cfg(windows)]
        attributes: md.file_attributes(),
        #[cfg(target_os = "linux")]
        attributes: md.permissions().mode(),
        contents: utf8_contents,
        is_modified: false,
        content_diff: "".to_string(),
        content_diff_readable: "".to_string(),
        #[cfg(windows)]
        discretionary_acl: dacl_result,
        #[cfg(windows)]
        system_acl: sacl_result,
    };

    // Check if the file was modified and update flag
    debug!("checking if file is_modified");
    filescanresult.is_modified = check_file_modified(last_scan, &filescanresult);

    /*
    Since there's no way (with our current data structure) to tell if a file had all lines added
    or removed, vs us just not scanning content the last time around... we have to just take
    the results and pass it to the diff comparison for content
    We can at least validate that content scan was on for this run though.
    Assuming all of the scenarios that trigger is_modified come back false, then if content
    scanning is on, we will collect "new" content this run, but won't show any differences.
    Even if hashes were all off on the last run, we will won't flag a content modification unless
    at least one criteria was measurably different from the prior run.

    Scenario: Scan 1 has content on, Scan 2 has content off
    Result: We will not collect content and we will not show content differences

    Scenario: Scan 1 has content off, Scan 2 has content off
    Result: We will not collect content and we will not show content differences

    Scenario: Scan 1 has content on, Scan 2 has content on
    Result: We will collect content and we will show content differences

    Scenario: Scan 1 has content off, Scan 2 has content on
    Result: We will collect content and we will show content differences as if every line was
    an addition
    */
    if settings.file_content && filescanresult.is_modified {
        debug!("File is_modified: Checking content diffs");
        let (content_diff, content_diff_readable) = get_content_diff(&filescanresult, last_scan);

        filescanresult.content_diff = content_diff;
        filescanresult.content_diff_readable = content_diff_readable;
    }

    filescanresult
}

pub fn get_content_diff(
    new_scan: &FileScanResult,
    old_scan_results: &Vec<FileScanResult>,
) -> (String, String) {
    for scan_entry in old_scan_results {
        if !scan_entry.path.eq(&new_scan.path) {
            continue;
        }
        debug!("Found matching prior scan entry");
        let diff_result = diff_lines(&scan_entry.contents, &new_scan.contents);
        let result = diff_result
            .to_string()
            .replace(" [9;31m", "--[[") // Replace RED
            .replace(" [32m", "++[[") // Replace GREEN
            .replace("[0m", "]]"); // Replace RESET

        let mut readable_output = String::new();
        let mut line_counter = 0;
        for line in result.lines() {
            line_counter += 1;

            if line.contains("--[[") {
                readable_output.push_str(
                    String::from(format!("Line {}: {}\n", line_counter.to_string(), line)).as_str(),
                );
                // When dealing with a removed line, we need to decrement the line counter so our
                // final output line numbers match the file in the file system
                line_counter -= 1;
                continue;
            } else {
                readable_output.push_str(
                    String::from(format!("Line {}: {}\n", line_counter.to_string(), line)).as_str(),
                );
            }
        }

        // This removes the final line break that we unnecessarily added.
        readable_output.pop();
        return (result.to_string(), readable_output);
    }
    debug!("Found no matching prior scan entry: Returning empty diffs");
    return ("".to_string(), "".to_string());
}

pub fn check_file_modified(last_scan: &Vec<FileScanResult>, this_scan: &FileScanResult) -> bool {
    for scan_entry in last_scan {
        if &scan_entry.path != &this_scan.path {
            continue;
        }

        // We should have a matching path now
        // Missing files/dirs don't have hashes, so check existence first
        if !&scan_entry.exists.eq(&this_scan.exists) {
            return true;
        }

        // Check that we have hashes on both results, then compare for changes
        if &scan_entry.blake2s != ""
            && this_scan.blake2s != ""
            && !&scan_entry.blake2s.eq(&this_scan.blake2s)
            || &scan_entry.sha256 != ""
                && this_scan.sha256 != ""
                && !&scan_entry.sha256.eq(&this_scan.sha256)
            || &scan_entry.md5 != "" && this_scan.md5 != "" && !&scan_entry.md5.eq(&this_scan.md5)
        {
            // Results have a different hash. File is modified
            debug!("File hashes differ: Path is_modified");
            return true;
        }

        debug!("File hashes do not differ: Checking metadata");
        // Hash data is not available for comparison. Check other parameters
        if !&scan_entry.attributes.eq(&this_scan.attributes) {
            return true;
        }
        // Compare sizes
        if !&scan_entry.size.eq(&this_scan.size) {
            return true;
        }
        // If RO settings were swapped, this is a permissions change
        if !&scan_entry.is_readonly.eq(&this_scan.is_readonly) {
            return true;
        }
        // If symlink status has changed, then technically we are looking at a symlink instead of
        // a file/dir, even if the resulting object of the symlink is the same file.
        // It's important to fail here before getting to ACLs since ultimately, ACLs in Windows
        // are a slower comparison. Given a lot of file ACLs are based on inheritance, doing any
        // symlink is likely to corrupt our permissions.
        if !&scan_entry.is_symbolic_link.eq(&this_scan.is_symbolic_link) {
            return true;
        }
        // T
        if !&scan_entry.modified_time.eq(&this_scan.modified_time) {
            return true;
        }
        // T
        if !&scan_entry.creation_time.eq(&this_scan.creation_time) {
            return true;
        }

        // Validate DACLs match
        #[cfg(windows)]
        if check_acl_modified(&scan_entry.discretionary_acl, &this_scan.discretionary_acl) {
            return true;
        }

        // Validate SACLs match
        #[cfg(windows)]
        if check_acl_modified(&scan_entry.system_acl, &this_scan.system_acl) {
            return true;
        }
    }
    // We've checked all metadata aspects and found no changes for our matching path
    debug!("File metadata matches");
    return false;
}

#[cfg(windows)]
pub fn check_acl_modified(old_acl: &WinAcl, new_acl: &WinAcl) -> bool {
    if old_acl.object_type == new_acl.object_type {
        // Check counts of acl entries
        if !old_acl.acl_entries.len().eq(&new_acl.acl_entries.len()) {
            return true;
        }

        // For each new entry, check if a matching old entry exists
        for new_entry in &new_acl.acl_entries {
            let mut matched_sid = false;
            for old_entry in &old_acl.acl_entries {
                // Check if the SIDs match in the ACL entry
                if !old_entry.acl_sid.eq(&new_entry.acl_sid) {
                    continue;
                }
                matched_sid = true;

                // Check the other ACL details
                if !old_entry.acl_type.eq(&new_entry.acl_type)
                    && !old_entry.acl_mask.eq(&new_entry.acl_mask)
                    && !old_entry.acl_user.eq(&new_entry.acl_user)
                    && !old_entry.acl_flags.eq(&new_entry.acl_flags)
                {
                    return true;
                }
                // Only get here if this_scan's entry had a matching old_entry AND if the
                // ACL details matched.
                break;
            }
            // Double check that we found a match
            if matched_sid {
                continue;
            }

            // No matching entry was found so ACLs may have same count, but at least one old
            // entry was removed and replaced with a different new entry. This shows that the
            // modification is true
            return true;
        }
        // We've checked all metadata and had nothing differ. This ACL is unchanged.
        return false;
    } else {
        // Non matching ACL types should automatically fail
        return true;
    }
}

use chrono::{DateTime, Utc};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::time::SystemTime;
#[cfg(windows)]
use {
    winapi::shared::minwindef::BYTE,
    windows_permissions::{LocalBox, Sid},
};

#[cfg(windows)]
#[allow(unused)]
pub fn get_cur_sid() -> Vec<BYTE> {
    // Todo add error handling for the unwraps
    let cur_user = windows_acl::helper::current_user();
    let cur_sid = windows_acl::helper::name_to_sid(&cur_user.unwrap().to_string(), None);

    cur_sid.unwrap()
}

use crate::file::FileScanResult;
use crate::osfig_state::OsfigSettings;
use crate::registry::{RegistryResult, RegistryResults};
#[cfg(target_os = "linux")]
use users;

#[allow(unused)]
pub fn get_cur_username() -> String {
    #[cfg(windows)]
    return windows_acl::helper::current_user().unwrap();

    #[cfg(target_os = "linux")]
    return users::get_effective_username()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
}

#[allow(unused)]
#[cfg(windows)]
pub fn sid_to_username(sid: &String) -> (String, String) {
    // Todo add error handling for the unwraps
    // Construct ACL System\Username
    let acl_sid: LocalBox<Sid> = sid.parse().unwrap();
    let result = windows_permissions::wrappers::LookupAccountSid(acl_sid.as_ref()).unwrap();
    let system_name = result.1.to_str().unwrap();
    let user_name = result.0.to_str().unwrap();

    (system_name.to_string(), user_name.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub files: Vec<FileScanResult>,
    pub registry: RegistryResults,
}

impl Default for ScanResults {
    fn default() -> Self {
        Self {
            files: vec![],
            registry: RegistryResults { results: vec![] },
        }
    }
}

impl ScanResults {
    pub fn add_file(&mut self, file: FileScanResult) {
        self.files.push(file)
    }
    pub fn add_files(&mut self, files: Vec<FileScanResult>) {
        for file in files {
            self.files.push(file)
        }
    }

    pub fn add_registry(&mut self, registry: RegistryResult) {
        self.registry.results.push(registry)
    }
    pub fn replace_registries(&mut self, registries: RegistryResults) {
        self.registry = registries
    }

    pub fn add_registries(&mut self, registries: RegistryResults) {
        for registry in registries.results {
            self.registry.results.push(registry)
        }
    }
}

pub fn save_results_to_file(results: ScanResults, osfig_settings: &OsfigSettings) {
    // I'm torn on this and may change it later. If the results are 0 it just saved "[]" into the
    // json. Currently we're skipping the save operation and putting a message in the log. For
    // integrity purposes, it may be valuable to store the empty json result instead. Will need to
    // reconsider this later.

    if results.files.len() == 0 && results.registry.results.len() == 0 {
        warn!("Found no results to save. Validate scan settings, access/permissions, and errors in the log");
        return;
    }

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

pub fn store_json(results: &ScanResults, path: &str) -> Result<(), std::io::Error> {
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

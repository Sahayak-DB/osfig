use serde::{Deserialize, Serialize};

#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
pub struct FileHashes {
    pub(crate) md5: bool,
    pub(crate) sha256: bool,
    pub(crate) blake2s: bool,
}

#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanSettings {
    pub(crate) scan_files: bool,
    pub(crate) file_patterns: Vec<String>,
    pub(crate) file_ignore_patterns: Vec<String>,
    pub(crate) file_hashes: FileHashes,
    pub(crate) file_dacl: bool,
    pub(crate) file_sacl: bool,
    pub(crate) file_content: bool,
    pub(crate) file_scan_delay: u16,
    pub(crate) scan_registry: bool,
    pub(crate) registry_patterns: Vec<String>,
}

pub fn get_default_scan_settings() -> ScanSettings {
    let scan_settings = ScanSettings {
        scan_files: true,
        file_patterns: get_default_file_paths(),
        file_ignore_patterns: get_default_ignore_file_paths(),
        file_hashes: FileHashes {
            md5: true,
            sha256: true,
            blake2s: false,
        },
        file_dacl: true,
        file_sacl: false,
        file_content: true,
        file_scan_delay: 0,
        scan_registry: true,
        registry_patterns: get_default_registry_paths(),
    };

    scan_settings
}

fn get_default_file_paths() -> Vec<String> {
    let mut patterns = Vec::new();
    patterns.push("C:\\autoexec.bat".to_string());
    patterns.push("C:\\boot.ini".to_string());
    patterns.push("C:\\config.sys".to_string());
    patterns.push("C:\\Windows\\*.exe".to_string());
    patterns.push("C:\\Windows\\*.ini".to_string());
    patterns.push("C:\\Windows\\*.dll".to_string());
    patterns.push("C:\\Windows\\System32".to_string());
    patterns.push("C:\\Windows\\System32\\*.exe".to_string());
    patterns.push("C:\\Windows\\System32\\*.ini".to_string());
    patterns.push("C:\\Windows\\System32\\*.dll".to_string());

    patterns
}
fn get_default_ignore_file_paths() -> Vec<String> {
    let patterns = Vec::new();

    patterns
}

fn get_default_registry_paths() -> Vec<String> {
    let patterns = Vec::new();

    patterns
}

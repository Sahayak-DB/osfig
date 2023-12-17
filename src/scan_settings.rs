use serde::{Deserialize, Serialize};

#[allow(unused)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashes {
    pub(crate) md5: bool,
    pub(crate) sha256: bool,
    pub(crate) blake2s: bool,
}

#[allow(unused)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScanSetting {
    pub(crate) file_patterns: Vec<String>,
    pub(crate) file_ignore_patterns: Vec<String>,
    pub(crate) file_hashes: FileHashes,
    pub(crate) file_dacl: bool,
    pub(crate) file_sacl: bool,
    pub(crate) file_content: bool,
    pub(crate) file_read_buffer_size: u64,
}

#[allow(unused)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSettings {
    pub(crate) scan_files: bool,
    pub(crate) file_scan_settings: Vec<FileScanSetting>,
    pub(crate) file_scan_delay: u16,
    pub(crate) scan_registry: bool,
    pub(crate) registry_patterns: Vec<String>,
}

pub fn get_default_scan_settings() -> ScanSettings {
    let mut scan_settings = ScanSettings {
        scan_files: true,
        file_scan_settings: Vec::new(),
        file_scan_delay: 0,
        scan_registry: true,
        registry_patterns: get_default_registry_paths(),
    };

    scan_settings.file_scan_settings.push(FileScanSetting {
        file_patterns: get_default_file_paths("windows"),
        file_ignore_patterns: get_default_ignore_file_paths("windows"),
        file_hashes: FileHashes {
            md5: true,
            sha256: true,
            blake2s: false,
        },
        file_dacl: true,
        file_sacl: false,
        file_content: false,
        file_read_buffer_size: crate::osfig_state::DEFAULT_FILE_READ_BUFFER_SIZE,
    });

    scan_settings.file_scan_settings.push(FileScanSetting {
        file_patterns: get_default_file_paths("linux"),
        file_ignore_patterns: get_default_ignore_file_paths("linux"),
        file_hashes: FileHashes {
            md5: true,
            sha256: true,
            blake2s: false,
        },
        file_dacl: false,
        file_sacl: false,
        file_content: false,
        file_read_buffer_size: crate::osfig_state::DEFAULT_FILE_READ_BUFFER_SIZE,
    });

    scan_settings
}

const WINDOWS_FILE_PATTERNS: [&str; 15] = [
    "C:\\*.bat",
    "C:\\*.ini",
    "C:\\*.sys",
    "C:\\Windows",
    "C:\\Windows\\*.exe",
    "C:\\Windows\\*.ini",
    "C:\\Windows\\*.sys",
    "C:\\Windows\\*.dll",
    "C:\\Windows\\System32",
    "C:\\Windows\\System32\\*.exe",
    "C:\\Windows\\System32\\*.ini",
    "C:\\Windows\\System32\\*.sys",
    "C:\\Windows\\System32\\*.dll",
    "C:\\Windows\\System32\\drivers\\etc",
    "C:\\Windows\\System32\\drivers\\etc\\*",
];

const LINUX_FILE_PATTERNS: [&str; 28] = [
    "/boot",
    "/root",
    "/root/.ssh",
    "/.ssh/**",
    "/home/*/.ssh/**",
    "/etc",
    "/etc/*",
    "/lib/",
    "/lib/*",
    "/lib64/",
    "/lib64/*",
    "/bin",
    "/bin/*",
    "/sbin",
    "/sbin/*",
    "/usr/bin",
    "/usr/bin/*",
    "/usr/local/bin",
    "/usr/local/bin/*",
    "/usr/local/sbin",
    "/usr/local/sbin/*",
    "/usr/sbin",
    "/usr/sbin/*",
    "/usr/share/keyrings",
    "/usr/libexec/openssh",
    "/usr/libexec/openssh/*",
    "/usr/kerberos/bin",
    "/usr/kerberos/bin/*",
];

fn get_default_file_paths(os: &str) -> Vec<String> {
    if os == "windows" {
        WINDOWS_FILE_PATTERNS
            .iter()
            .map(|&s| s.to_string())
            .collect()
    } else if os == "linux" {
        LINUX_FILE_PATTERNS.iter().map(|&s| s.to_string()).collect()
    } else {
        Vec::new()
    }
}

const WINDOWS_IGNORE_PATTERNS: [&str; 1] = ["C:\\Windows\\Temp"];

const LINUX_IGNORE_PATTERNS: [&str; 1] = ["/var/log"];

fn get_default_ignore_file_paths(os: &str) -> Vec<String> {
    if os == "windows" {
        WINDOWS_IGNORE_PATTERNS
            .iter()
            .map(|&s| s.to_string())
            .collect()
    } else if os == "linux" {
        LINUX_IGNORE_PATTERNS
            .iter()
            .map(|&s| s.to_string())
            .collect()
    } else {
        Vec::new()
    }
}

const WINDOWS_REGISTRY_PATTERNS: [&str; 1] =
    ["HKEY_LOCAL_MACHINE::SOFTWARE\\Python\\PythonCore|DisplayName"];

fn get_default_registry_paths() -> Vec<String> {
    WINDOWS_REGISTRY_PATTERNS
        .iter()
        .map(|&s| s.to_string())
        .collect()
}

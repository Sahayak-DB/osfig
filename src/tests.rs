//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////       HELPERS      ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod helpers_tests {
    use crate::helpers::*;
    use std::any::Any;

    #[test]
    #[cfg(windows)]
    fn test_get_cur_sid_type() {
        // Validate return type of interface in windows_acl crate
        // Should error if return type changes or if unable to execute win API calls
        let expected_type: Vec<winapi::shared::minwindef::BYTE> =
            Vec::with_capacity(winapi::ctypes::c_uchar::default().into());
        assert_eq!(get_cur_sid().type_id(), expected_type.type_id());
    }

    #[test]
    fn test_get_cur_username_type() {
        // Validate return type of interface in windows_acl crate
        // Should error if return type changes or if unable to execute win API calls
        let expected_type: String = String::from("");
        assert_eq!(get_cur_username().type_id(), expected_type.type_id());
    }

    #[test]
    #[cfg(windows)]
    fn test_sid_to_username_value() {
        // Validate a well known SID output
        let well_known_sid: String = "S-1-5-18".to_string();
        if sid_to_username(&well_known_sid) == ("NT AUTHORITY".to_string(), "SYSTEM".to_string()) {
            assert!(true)
        } else {
            assert!(false)
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_sid_to_username_type() {
        // Validate a well known SID output
        let well_known_sid: String = "S-1-5-18".to_string();
        assert_eq!(
            sid_to_username(&well_known_sid).type_id(),
            ("NT AUTHORITY".to_string(), "SYSTEM".to_string()).type_id()
        )
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////        FILE        ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod file_tests {
    use crate::file::*;
    use crate::osfig_state::OsfigSettings;
    use crate::scan_settings::{FileScanSetting, ScanSettings};
    #[cfg(windows)]
    use crate::win_acl::{WinAcl, WinaclEntry};
    use std::any::Any;
    use std::fs::File;
    use std::path::{Path, PathBuf};

    fn setup_file_tests() {
        teardown_file_tests();
        let dirs: Vec<&str> = vec!["./scans"];
        for dir in dirs {
            let _ = match std::fs::create_dir_all(dir) {
                Ok(_) => {
                    assert!(true)
                }
                Err(_) => {
                    assert!(false)
                }
            };
        }
        let files: Vec<&str> = vec!["testfile1", "testfile2"];
        for file in files {
            let _ = match File::create(file) {
                Ok(_) => {
                    assert!(true)
                }
                Err(_) => {
                    assert!(false)
                }
            };
        }
        // Tests run too fast on some systems causing intermittent failures.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    fn teardown_file_tests() {
        let files: Vec<&str> = vec!["testfile1", "testfile2", "tests_result.json", "tests.json"];
        let dirs: Vec<&str> = vec!["./scans"];

        for file in files {
            let _ = std::fs::remove_file(file);
        }

        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
        // Tests run too fast on some systems causing intermittent failures.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    #[test]
    #[cfg(windows)]
    fn test_filescanresult_format_win() {
        // Validate the windows specific values types have not been modified in the win_acl crate.
        let expected_value: FileScanResult = FileScanResult::default();

        assert_eq!(expected_value.dacl.object_type, "".to_string());

        assert_eq!(
            expected_value.sacl.acl_entries.type_id(),
            Vec::<WinaclEntry>::new().type_id()
        );
    }

    #[test]
    fn test_filescanresult_set_path() {
        // Test field types from external crates have not been modified
        let mut expected_value: FileScanResult = FileScanResult::default();

        assert_eq!(expected_value.path, Box::new(PathBuf::from(Path::new(""))));

        expected_value.set_path_from_str("./Test/");
        assert_eq!(
            expected_value.path,
            Box::new(PathBuf::from(Path::new("./Test/")))
        );
    }

    #[test]
    fn test_store_json() {
        //
        let expected_value: FileScanResult = FileScanResult::default();
        match store_json(&vec![expected_value], "tests.json") {
            Ok(_) => {
                assert!(true);
                teardown_file_tests()
            }
            Err(_) => {
                assert!(false)
            }
        }
        // An empty file handle should fail, even with our path override
        // as there won't be a filename
        let expected_value: FileScanResult = FileScanResult::default();
        match store_json(&vec![expected_value], "") {
            Ok(_) => {
                assert!(false)
            }
            Err(_) => {
                assert!(true)
            }
        }
    }
    #[test]
    fn test_find_latest_result_file() {
        //Todo after refactoring settings file to include results path
    }
    #[test]
    fn test_get_latest_results() {
        //Todo after refactoring settings file to include results path
    }
    #[test]
    fn test_scan_files() {
        setup_file_tests();

        #[cfg(windows)]
        let filescansetting = FileScanSetting {
            file_patterns: vec!["testfile*".to_string()],
            file_ignore_patterns: vec!["testfile2".to_string()],
            file_hashes: crate::scan_settings::FileHashes {
                md5: true,
                sha256: true,
                blake2s: true,
            },
            file_dacl: false,
            file_sacl: false,
            file_content: false,
        };
        #[cfg(target_os = "linux")]
        let filescansetting = FileScanSetting {
            file_patterns: vec!["testfile*".to_string()],
            file_ignore_patterns: vec!["testfile2".to_string()],
            file_hashes: crate::scan_settings::FileHashes {
                md5: true,
                sha256: true,
                blake2s: true,
            },
            file_dacl: false,
            file_sacl: false,
            file_content: false,
        };

        let osfig_settings = OsfigSettings {
            scan_settings: ScanSettings {
                scan_files: false,
                file_scan_settings: vec![filescansetting],
                file_scan_delay: 0,
                scan_registry: false,
                registry_patterns: vec![],
            },
        };

        let expected_value = scan_files(&osfig_settings);

        assert_eq!(
            expected_value.type_id(),
            vec![FileScanResult::default()].type_id()
        );
        assert_eq!(expected_value.len(), 1);

        let json_file = File::create("tests_result.json").unwrap();
        let file_writer = std::io::BufWriter::new(json_file);
        let _ = serde_json::to_writer_pretty(file_writer, &expected_value);

        let expected_value0 = expected_value.get(0).unwrap();
        assert_eq!(
            expected_value0.type_id(),
            FileScanResult::type_id(&Default::default())
        );
        assert_eq!(expected_value0.is_file, true);
        assert_eq!(expected_value0.exists, true);
        assert_eq!(expected_value0.path, Box::new(PathBuf::from("testfile1")));
        assert_eq!(expected_value0.is_modified, false);
        assert!(expected_value0.ctime.len() >= 23 && expected_value0.ctime.len() <= 33);
        assert!(expected_value0.mtime.len() >= 23 && expected_value0.ctime.len() <= 33);
        assert_eq!(expected_value0.is_sym, false);
        assert_eq!(expected_value0.is_dir, false);
        assert_eq!(expected_value0.is_readonly, false);
        assert_eq!(expected_value0.size, 0);
        #[cfg(windows)]
        assert_eq!(
            expected_value0.dacl.type_id(),
            WinAcl {
                object_type: "".to_string(),
                acl_entries: vec![]
            }
            .type_id()
        );

        // Recreating the file will cause the timestamps to be altered, so our next scan is
        // for a modified file. Also change to RO file.
        std::fs::remove_file("testfile1");
        let test_file = File::create("testfile1");
        let mut test_file_perms = test_file.unwrap().metadata().unwrap().permissions();
        test_file_perms.set_readonly(true);
        std::fs::set_permissions("testfile1", test_file_perms);

        let expected_value = scan_files(&osfig_settings);

        let json_file = File::create("tests_result.json").unwrap();
        let file_writer = std::io::BufWriter::new(json_file);
        let _ = serde_json::to_writer_pretty(file_writer, &expected_value);

        let expected_value0 = expected_value.get(0).unwrap();
        assert_eq!(
            expected_value0.type_id(),
            FileScanResult::type_id(&Default::default())
        );
        assert_eq!(expected_value0.is_file, true);
        assert_eq!(expected_value0.exists, true);
        assert_eq!(expected_value0.path, Box::new(PathBuf::from("testfile1")));
        assert_eq!(expected_value0.is_modified, true);
        assert!(expected_value0.ctime.len() >= 23 && expected_value0.ctime.len() <= 33);
        assert!(expected_value0.mtime.len() >= 23 && expected_value0.ctime.len() <= 33);
        assert_eq!(expected_value0.is_sym, false);
        assert_eq!(expected_value0.is_dir, false);
        assert_eq!(expected_value0.is_readonly, true);
        assert_eq!(expected_value0.size, 0);
        #[cfg(windows)]
        assert_eq!(
            expected_value0.dacl.type_id(),
            WinAcl {
                object_type: "".to_string(),
                acl_entries: vec![]
            }
            .type_id()
        );

        let test_file = File::open("testfile1");
        let mut test_file_perms = test_file.unwrap().metadata().unwrap().permissions();
        test_file_perms.set_readonly(false);
        std::fs::set_permissions("testfile1", test_file_perms);
        teardown_file_tests();
    }
    #[test]
    fn test_get_content_diff() {}
    #[test]
    fn test_check_acl_modified() {}
}
//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////       HASHING      ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod hashing_tests {
    use crate::hashing::*;
    use std::any::Any;

    #[test]
    fn test_example() {
        // Placeholder
        let expected_type: String = String::from("");
        assert_eq!(String::from("").type_id(), expected_type.type_id());
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////      LOGGING       ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod logging_tests {
    use crate::logging::*;
    use std::any::Any;

    #[test]
    fn test_example() {
        // Placeholder
        let expected_type: String = String::from("");
        assert_eq!(String::from("").type_id(), expected_type.type_id());
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////     OSFIG_STATE    ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod osfig_state_tests {
    use crate::osfig_state::*;
    use std::any::Any;

    #[test]
    fn test_example() {
        // Placeholder
        let expected_type: String = String::from("");
        assert_eq!(String::from("").type_id(), expected_type.type_id());
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////      REGISTRY      ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod registry_tests {
    use std::any::Any;

    #[cfg(windows)]
    use crate::registry::*;

    #[test]
    fn test_example() {
        // Placeholder
        let expected_type: String = String::from("");
        assert_eq!(String::from("").type_id(), expected_type.type_id());
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////   SCAN_SETTINGS    ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod scan_settings_tests {
    use crate::scan_settings::*;
    use std::any::Any;

    #[test]
    fn test_example() {
        // Placeholder
        let expected_type: String = String::from("");
        assert_eq!(String::from("").type_id(), expected_type.type_id());
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////       WIN_ACL      ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod win_acl_tests {
    use std::any::Any;

    #[cfg(windows)]
    use crate::win_acl::*;

    #[test]
    fn test_example() {
        // Placeholder
        let expected_type: String = String::from("");
        assert_eq!(String::from("").type_id(), expected_type.type_id());
    }
}

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
        let files: Vec<&str> = vec!["./testfile1", "./testfile2"];
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
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    fn teardown_file_tests() {
        let files: Vec<&str> = vec![
            "./testfile1",
            "./testfile2",
            "tests_result.json",
            "tests.json",
        ];
        let dirs: Vec<&str> = vec!["./scans"];

        for file in files {
            let _ = std::fs::remove_file(file);
        }

        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
        // Tests run too fast on some systems causing intermittent failures.
        std::thread::sleep(std::time::Duration::from_millis(150));
    }

    #[test]
    #[cfg(windows)]
    fn test_filescanresult_format_win() {
        // Validate the windows specific values types have not been modified in the win_acl crate.
        let expected_value: FileScanResult = FileScanResult::default();

        assert_eq!(expected_value.discretionary_acl.object_type, "".to_string());

        assert_eq!(
            expected_value.system_acl.acl_entries.type_id(),
            Vec::<WinaclEntry>::new().type_id()
        );
    }

    #[test]
    fn test_filescanresult_set_path() {
        // Test field types from external crates have not been modified
        let mut expected_value: FileScanResult = FileScanResult::default();

        assert_eq!(expected_value.path, Box::new(PathBuf::from(Path::new(""))));

        expected_value.set_path("./Test/");
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
            file_patterns: vec!["./testfile*".to_string()],
            file_ignore_patterns: vec!["./testfile2".to_string()],
            file_hashes: crate::scan_settings::FileHashes {
                md5: true,
                sha256: true,
                blake2s: true,
            },
            file_dacl: false,
            file_sacl: false,
            file_content: false,
            file_read_buffer_size: 4096,
        };
        #[cfg(target_os = "linux")]
        let filescansetting = FileScanSetting {
            file_patterns: vec!["./testfile*".to_string()],
            file_ignore_patterns: vec!["./testfile2".to_string()],
            file_hashes: crate::scan_settings::FileHashes {
                md5: true,
                sha256: true,
                blake2s: true,
            },
            file_dacl: false,
            file_sacl: false,
            file_content: false,
            file_read_buffer_size: 4096,
        };

        let osfig_settings = OsfigSettings {
            scan_settings: ScanSettings {
                scan_files: true,
                file_scan_settings: vec![filescansetting],
                file_scan_delay: 0,
                scan_registry: false,
                registry_patterns: vec![],
            },
            scan_result_path: "./scans".to_string(),
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
        assert!(
            expected_value0.creation_time.len() >= 23 && expected_value0.creation_time.len() <= 33
        );
        assert!(
            expected_value0.modified_time.len() >= 23 && expected_value0.modified_time.len() <= 33
        );
        assert_eq!(expected_value0.is_symbolic_link, false);
        assert_eq!(expected_value0.is_dir, false);
        assert_eq!(expected_value0.is_readonly, false);
        assert_eq!(expected_value0.size, 0);
        #[cfg(windows)]
        assert_eq!(
            expected_value0.discretionary_acl.type_id(),
            WinAcl {
                object_type: "".to_string(),
                acl_entries: vec![]
            }
            .type_id()
        );

        // Recreating the file will cause the timestamps to be altered, so our next scan is
        // for a modified file. Also change to RO file.
        let _ = std::fs::remove_file("testfile1");
        let test_file = File::create("testfile1");
        let mut test_file_perms = test_file.unwrap().metadata().unwrap().permissions();
        test_file_perms.set_readonly(true);
        let _ = std::fs::set_permissions("testfile1", test_file_perms);

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
        assert!(
            expected_value0.creation_time.len() >= 23 && expected_value0.creation_time.len() <= 33
        );
        assert!(
            expected_value0.modified_time.len() >= 23 && expected_value0.modified_time.len() <= 33
        );
        assert_eq!(expected_value0.is_symbolic_link, false);
        assert_eq!(expected_value0.is_dir, false);
        assert_eq!(expected_value0.is_readonly, true);
        assert_eq!(expected_value0.size, 0);
        #[cfg(windows)]
        assert_eq!(
            expected_value0.discretionary_acl.type_id(),
            WinAcl {
                object_type: "".to_string(),
                acl_entries: vec![]
            }
            .type_id()
        );

        let test_file = File::open("./testfile1");
        let mut test_file_perms = test_file.unwrap().metadata().unwrap().permissions();
        test_file_perms.set_readonly(false);
        let _ = std::fs::set_permissions("testfile1", test_file_perms);
        teardown_file_tests();
    }
    #[test]
    fn test_get_content_diff() {
        //Todo after refactoring settings file to include results path
    }
    #[test]
    fn test_check_acl_modified() {
        //Todo after refactoring settings file to include results path
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////       HASHING      ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod hashing_tests {
    use crate::hashing::*;
    use crate::scan_settings::FileHashes;
    use std::any::Any;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    fn setup_hash_tests() {
        teardown_hash_tests();
        let example_text = String::from("Test contents");
        let mut testfile = File::create("./hashtestfile").unwrap();
        let _ = testfile.write_all(example_text.as_bytes());
        let _ = testfile.flush();

        // Tests run too fast on some systems causing intermittent failures.
        std::thread::sleep(std::time::Duration::from_millis(150));
    }

    fn teardown_hash_tests() {
        let files: Vec<&str> = vec!["./hashtestfile"];

        for file in files {
            let _ = std::fs::remove_file(file);
        }

        // Tests run too fast on some systems causing intermittent failures.
        std::thread::sleep(std::time::Duration::from_millis(150));
    }

    #[test]
    fn test_md5() {
        setup_hash_tests();
        // Placeholder
        let expected_value_md5: String = String::from("2CEDB0215290E9A96103135E2843FA79");
        assert_eq!(
            get_md5(Path::new("./hashtestfile"), 4096),
            expected_value_md5
        );
        teardown_hash_tests();
    }

    #[test]
    fn test_sha256() {
        setup_hash_tests();
        let expected_value_sha256: String =
            String::from("96640A0073CD72CB62AE9403105FB97D4635E7FF87658C1AF0034242B7BED840");
        assert_eq!(
            get_sha256(Path::new("./hashtestfile"), 4096),
            expected_value_sha256
        );
        teardown_hash_tests();
    }

    #[test]
    fn test_blake2s() {
        setup_hash_tests();
        let expected_value_blake2s: String =
            String::from("2F777E0B8C11400C57CCE39AA8741E759E5FE44C0D31016B4BB1714908AF4B9F");
        assert_eq!(
            get_blake2s(Path::new("./hashtestfile"), 4096),
            expected_value_blake2s
        );
        teardown_hash_tests();
    }
    #[test]
    fn test_hashes() {
        setup_hash_tests();

        // Check known hashes for all types
        let expected_hashes: HashValues = HashValues {
            md5: "2CEDB0215290E9A96103135E2843FA79".to_string(),
            sha256: "96640A0073CD72CB62AE9403105FB97D4635E7FF87658C1AF0034242B7BED840".to_string(),
            blake2s: "2F777E0B8C11400C57CCE39AA8741E759E5FE44C0D31016B4BB1714908AF4B9F".to_string(),
        };

        let hash_results = get_all_hashes(
            &FileHashes {
                md5: true,
                sha256: true,
                blake2s: true,
            },
            4096,
            Path::new("./hashtestfile"),
        );

        assert_eq!(hash_results.type_id(), expected_hashes.type_id());
        assert_eq!(expected_hashes.md5, hash_results.md5);
        assert_eq!(expected_hashes.sha256, hash_results.sha256);
        assert_eq!(expected_hashes.blake2s, hash_results.blake2s);

        // Validate config allows not grabbing some hashes
        // Honestly if you want to know why these tests are here, look at the hashing.rs file
        // that was updated in this same commit. Tests are your friend... but apparently I'm not
        let expected_hashes: HashValues = HashValues {
            md5: "2CEDB0215290E9A96103135E2843FA79".to_string(),
            sha256: "".to_string(),
            blake2s: "".to_string(),
        };
        let hash_results = get_all_hashes(
            &FileHashes {
                md5: true,
                sha256: false,
                blake2s: false,
            },
            4096,
            Path::new("./hashtestfile"),
        );
        assert_eq!(expected_hashes.md5, hash_results.md5);
        assert_eq!(expected_hashes.sha256, hash_results.sha256);
        assert_eq!(expected_hashes.blake2s, hash_results.blake2s);

        let expected_hashes: HashValues = HashValues {
            md5: "".to_string(),
            sha256: "96640A0073CD72CB62AE9403105FB97D4635E7FF87658C1AF0034242B7BED840".to_string(),
            blake2s: "".to_string(),
        };
        let hash_results = get_all_hashes(
            &FileHashes {
                md5: false,
                sha256: true,
                blake2s: false,
            },
            4096,
            Path::new("./hashtestfile"),
        );
        assert_eq!(expected_hashes.md5, hash_results.md5);
        assert_eq!(expected_hashes.sha256, hash_results.sha256);
        assert_eq!(expected_hashes.blake2s, hash_results.blake2s);

        let expected_hashes: HashValues = HashValues {
            md5: "".to_string(),
            sha256: "".to_string(),
            blake2s: "2F777E0B8C11400C57CCE39AA8741E759E5FE44C0D31016B4BB1714908AF4B9F".to_string(),
        };
        let hash_results = get_all_hashes(
            &FileHashes {
                md5: false,
                sha256: false,
                blake2s: true,
            },
            4096,
            Path::new("./hashtestfile"),
        );
        assert_eq!(expected_hashes.md5, hash_results.md5);
        assert_eq!(expected_hashes.sha256, hash_results.sha256);
        assert_eq!(expected_hashes.blake2s, hash_results.blake2s);

        teardown_hash_tests();
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////      LOGGING       ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod logging_tests {
    use crate::logging::*;
    use log::info;
    use std::any::Any;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    fn setup_logging_tests() {
        teardown_logging_tests();
        setup_logging();
    }

    fn teardown_logging_tests() {
        let files: Vec<&str> = vec!["./config/osfig_log_settings.yml", "./logs/osfig.log"];

        for file in files {
            let _ = std::fs::remove_file(file);
        }

        // Tests run too fast on some systems causing intermittent failures.
        std::thread::sleep(std::time::Duration::from_millis(150));
    }

    #[test]
    fn test_logging() {
        setup_logging_tests();
        let test_string = "Test 123 asdf";
        info!("{}", test_string);

        if Path::new("./logs/osfig.log").exists() {
            assert!(true);
        } else {
            assert!(false);
        }

        let expected_type = String::new();
        assert_eq!(
            return_default_logging_config().type_id(),
            expected_type.type_id()
        );

        let log_config_file = File::open("./config/osfig_log_settings.yml");
        let mut log_contents = Vec::new();
        log_config_file
            .unwrap()
            .read_to_end(&mut log_contents)
            .unwrap();

        assert_eq!(return_default_logging_config().into_bytes(), log_contents);

        let logfile = File::open("./logs/osfig.log");
        let mut log_contents = Vec::new();
        logfile.unwrap().read_to_end(&mut log_contents).unwrap();

        let log_contents = String::from_utf8(log_contents).unwrap();
        assert!(log_contents.contains(test_string));

        teardown_logging_tests();
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////     OSFIG_STATE    ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod osfig_state_tests {
    use crate::osfig_state::*;
    use crate::scan_settings::{FileScanSetting, ScanSettings};
    use std::any::Any;

    fn setup_settings_tests() {
        teardown_settings_tests();

        // This will trigger creation of a default settings file
        load_osfig_settings();

        // Tests run too fast on some systems causing intermittent failures.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    fn teardown_settings_tests() {
        let files: Vec<&str> = vec!["./config/osfig_settings.json"];

        for file in files {
            let _ = std::fs::remove_file(file);
        }

        // Tests run too fast on some systems causing intermittent failures.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    #[test]
    fn test_default_settings() {
        setup_settings_tests();
        let expected_value = load_osfig_settings();

        assert_eq!(
            expected_value.type_id(),
            OsfigSettings {
                scan_settings: ScanSettings {
                    scan_files: false,
                    file_scan_settings: vec![],
                    file_scan_delay: 0,
                    scan_registry: false,
                    registry_patterns: vec![],
                },
                scan_result_path: "./scans".to_string(),
            }
            .type_id()
        );

        teardown_settings_tests();
    }

    #[test]
    fn test_load_settings() {
        setup_settings_tests();
        let expected_value = load_osfig_settings();

        assert_eq!(expected_value.scan_settings.file_scan_delay, 0);
        assert_eq!(
            expected_value.scan_settings.file_scan_settings.type_id(),
            Vec::<FileScanSetting>::new().type_id()
        );
        assert_eq!(
            expected_value.scan_settings.registry_patterns.type_id(),
            Vec::<String>::new().type_id()
        );
        assert_eq!(expected_value.scan_settings.scan_files, true);
        assert_eq!(expected_value.scan_settings.scan_registry, true);

        teardown_settings_tests();
    }

    #[test]
    fn test_save_settings() {
        setup_settings_tests();
        let expected_value = load_osfig_settings();

        assert_eq!(
            expected_value.type_id(),
            OsfigSettings {
                scan_settings: ScanSettings {
                    scan_files: false,
                    file_scan_settings: vec![],
                    file_scan_delay: 0,
                    scan_registry: false,
                    registry_patterns: vec![],
                },
                scan_result_path: "./scans".to_string(),
            }
            .type_id()
        );

        teardown_settings_tests();
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////      REGISTRY      ///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
#[cfg(windows)]
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

use crate::scan_settings::{get_default_scan_settings, ScanSettings};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use std::fs;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;
use std::process::exit;
use std::string::ToString;

// Settings defaults
const MAX_FILE_SCAN_DELAY: u16 = 10000;
const DEFAULT_SCANS_SAVE_PATH: &'static str = "./scans";

#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
pub struct OsfigSettings {
    pub(crate) scan_settings: ScanSettings,
    pub(crate) scan_result_path: String,
}

pub fn print_usage() {
    let terminal_width: u16 = 96;
    let mut output_width: usize = (terminal_width as f32 * 0.667) as usize;
    if output_width % 2 == 1 {
        if output_width < usize::MAX {
            output_width += 1;
        } else {
            output_width -= 1
        }
    }
    let section_size: usize = (output_width - 13) / 2;

    print_banner();
    println!("\x1b[0;94m{:=<output_width$}\x1b[0m", "");
    println!(
        "\x1b[0;94m{:=<section_size$} {} v{} {:=<section_size$}\x1b[0m",
        "",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        ""
    );
    println!("\x1b[0;94m{:=<output_width$}\x1b[0m", "");
    println!("{}", env!("CARGO_PKG_REPOSITORY"));

    // Todo Add a verbose output option switch
    // println!(
    //     "{}.{}.{}",
    //     env!("CARGO_PKG_VERSION_MAJOR"),
    //     env!("CARGO_PKG_VERSION_MINOR"),
    //     env!("CARGO_PKG_VERSION_PATCH")
    // )
}

fn print_banner() {
    // Todo is it possible to detect when a terminal doesn't support color output?

    const COLOR_SOLID: &str = "\x1b[0;95m";
    const COLOR_SHADOW: &str = "\x1b[0;94m";
    const COLOR_RESET: &str = "\x1b[0m";

    const CHAR_SOLID: &str = "█";
    const CHAR_SHADOW: &str = "░";

    const ASCII_LOGO: &str = "\n
     ███████      █████████   ███████████ ██████    ████████
    ███░░░░░███   ███░░░░░███ ░░███░░░░░  ░░███    ███░░░░░███
   ███     ░░███ ░███    ░░░   ░███   █    ░███   ███     ░░░
  ░███      ░███  ░█████████   ░███████    ░███  ░███
  ░███      ░███  ░░░░░░░░███  ░███░░░█    ░███  ░███    █████
  ░░███     ███   ███    ░███  ░███  ░     ░███  ░░███  ░░███
   ░░███████░    ░█████████   █████       ██████  ░░████████
     ░░░░░░░      ░░░░░░░░░   ░░░░░       ░░░░░░    ░░░░░░░░
    ";

    println!();
    for ascii_char in ASCII_LOGO.chars() {
        if ascii_char.to_string().as_str() == CHAR_SOLID {
            print!("{}{}", COLOR_SOLID, ascii_char);
        } else if ascii_char.to_string().as_str() == CHAR_SHADOW {
            print!("{}{}", COLOR_SHADOW, ascii_char);
        }
        if ascii_char.is_ascii_whitespace() || ascii_char.is_control() {
            print!("{}", ascii_char);
        }
    }
    println!("\x1b[0m");
}

fn get_default_settings() -> OsfigSettings {
    let osfig_settings = OsfigSettings {
        scan_settings: get_default_scan_settings(),
        scan_result_path: DEFAULT_SCANS_SAVE_PATH.to_string(),
    };

    osfig_settings
}

pub fn save_osfig_settings(settings: OsfigSettings) {
    // Save settings to a json file
    let path = Path::new("./config/osfig_settings.json");
    let config_dir = Path::new(&path).parent().unwrap();
    if !config_dir.exists() {
        match fs::create_dir_all(config_dir) {
            Ok(_) => {
                info!("Created ./config/ directory")
            }
            Err(e) => {
                error!("Cannot create config directory: {}", e)
            }
        };
        // Pause briefly to give the file system a moment to catch up
        // This fixes the intermittent testing errors on some systems
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let mut json_file = File::create(&path).unwrap();
    let file_writer = BufWriter::new(&json_file);
    let storage_result = serde_json::to_writer_pretty(file_writer, &settings);
    match storage_result {
        Ok(_) => {
            info!("Config saved to file {}", &path.to_str().unwrap())
        }
        Err(e) => {
            error!("Error writing JSON: {}", e)
        }
    }
    let _ = json_file.flush();
    // Pause briefly to give the file system a moment to catch up
    // This fixes the intermittent testing errors on some systems
    std::thread::sleep(std::time::Duration::from_millis(50));
}

pub fn load_osfig_settings() -> OsfigSettings {
    // Attempt to load settings from json
    let path = Path::new("./config/osfig_settings.json");
    let config_dir = Path::new(&path).parent().unwrap();

    if !path.exists() {
        warn!("Config file missing: Recreating default config");
        // If config directory is missing, create default config in location
        if !config_dir.exists() {
            warn!("Config directory missing: Recreating default path");
        }

        // This creates the path and file, but I wanted a second log entry to aid users into
        // understanding why it was missing to begin with.
        save_osfig_settings(get_default_settings());
    }

    // Load config
    let mut settings_file = match File::open(path) {
        Ok(file) => file,
        Err(_) => {
            panic!("Cannot open settings file.")
        }
    };

    let mut data: String = "".to_string();
    match settings_file.read_to_string(&mut data) {
        Ok(_) => {}
        Err(_) => {
            error!("Unable to read settings file. Aborting!");
            error!("Troubleshooting: Move the config file to another location and let OSFIG create a new one: Add your customizations back manually: Save in UTF-8, no BOM");
            exit(1);
        }
    };

    let mut settings: OsfigSettings = from_str(data.as_ref()).unwrap();
    // If you don't enforce a maximum, someone will use a u16. Nobody needs to pause for 1:05 min
    // between file scans. 10s is more than reasonable--excessive, actually.

    if settings.scan_settings.file_scan_delay > MAX_FILE_SCAN_DELAY {
        reset_delay(&mut settings.scan_settings);
    }

    // If they provide no path, use the default directory.
    if is_bad_scan_save_path(&settings.scan_result_path) {
        settings.scan_result_path = DEFAULT_SCANS_SAVE_PATH.to_string();
    }

    settings
}

fn reset_delay(scan_settings: &mut ScanSettings) {
    warn!("Invalid setting configuration: file_scan_delay: See documentation");
    scan_settings.file_scan_delay = MAX_FILE_SCAN_DELAY;
}

fn is_bad_scan_save_path(path: &String) -> bool {
    if path.is_empty() || path.ends_with("/") || path.ends_with("\\") {
        warn!("Invalid setting configuration: scan_result_path: See documentation");
        false
    } else {
        true
    }
}

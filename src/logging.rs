use log4rs;
use std::fs;
use std::fs::File;
use std::path::Path;

pub fn setup_logging() {
    let config_path = Path::new("./config/osfig_log_settings.yml");

    // Check file existence to see if it needs to be created before loading an empty file handle
    if !config_path.exists() {
        println!("Missing log configuration file. Recreating.");
        let parent_dir = config_path.parent().unwrap();

        // This should create all layers needed in case we ever change the log dir location
        std::fs::create_dir_all(parent_dir).unwrap();

        // Attempt to create the config file in the path. This should fail if we don't have
        // file system access. Otherwise, this is an owned directory subordinate to OSFIG, so
        // inherited permissions should usually give us access rights.
        let result = File::create(config_path);
        if result.is_err() {
            println!("Unable to access self-owned directory. Aborting!");
            panic!("Problem opening the file: ./config/osfig_log_settings.yml")
        }

        // Write the templated config contents into our new file handle
        let config_contents = return_default_config();
        let result_write = fs::write(config_path, config_contents);

        // Again, this should definitely work if we had access to create the file. Then again, I've
        // seen crazier sets of user permissions before. I mean, who CHMODs with 400? I would
        // expect a 200 or 600 to be in place if we could create the file.
        if result_write.is_err() {
            println!("Unable to access self-owned directory. Aborting!");
            panic!("Problem opening the file: ./config/osfig_log_settings.yml")
        }
        println!("Recreated default logging configuration. Set to ISO 8601 and UTC.");
    }

    // Todo Change later when we establish an OSFIG config file and allow user specified paths
    let init_result = log4rs::init_file("./config/osfig_log_settings.yml", Default::default());

    // If we can't access this path, someone has dome something very wrong. Shame on them.
    if init_result.is_err() {
        println!("Unable to establish logging. Aborting!");
        panic!("Problem opening the file: ./config/osfig_log_settings.yml")
    }
}

fn return_default_config() -> String {
    // This is a template for the default config file. Doing this makes it convenient to establish
    // a replacement file, but creates a release headache by requiring edits in two places. I'll
    // live with it though. Users are going to user, so might as well cater to their needs.
    let config = "appenders:
  stdout:
    kind: console

  # Appender for the rolling log w/ archival
  rolling:
    kind: rolling_file
    path: logs/osfig.log
    encoder:
      pattern: \"{d(%Y-%m-%dT%H:%M:%S %Z)(utc)} | {({level}):5.5} | {file}:{line} — {message}{n}\"
    policy:
      trigger:
        kind: size
        limit: 10 mb
      roller:
        kind: fixed_window
        pattern: logs/archive/osfig_log_{}.gz
        count: 10
        base: 1

root:
  level: info
  appenders:
    - rolling

loggers:
  rolling:
    level: info
    appenders:
      - rolling";
    config.to_string()
}

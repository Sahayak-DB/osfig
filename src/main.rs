use crate::win_helpers::get_cur_username;
use log::info;
use std::env::args;

mod file;
mod hashing;
mod logging;
mod osfig_state;
mod registry;
mod win_acl;
mod win_helpers;

fn main() -> std::io::Result<()> {
    logging::setup_logging();

    info!(
        "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
    );
    info!("Logging setup completed");
    info!("Initializing OSFIG");
    crate::osfig_state::print_usage();
    info!("Current Running User: {}", get_cur_username());

    // Testing file hashing
    // Grab args, drop the 0th, and boogie
    let mut options: Vec<String> = args().collect();
    options.remove(0);
    let mut pattern = ".\\test files\\*";
    if options.len() == 1 {
        pattern = options.get(0).unwrap();
    }

    file::scan_files(pattern);
    info!("File scanning complete");

    registry::scan_reg_keys();
    info!("Registry scanning complete");

    Ok(())
}

// Todo Configuration file for runtime directions
// Todo Store scans in local db for comparisons
// Todo Show only changed files in output
// Todo Show all results in ultra-verbose mode
// Todo Show contents diffs in verbose mode
// Todo Set up a build pipeline that automatically addresses versioning
// Todo Add commandline options

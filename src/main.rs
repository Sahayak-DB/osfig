use crate::osfig_state::load_osfig_settings;
#[cfg(windows)]
use crate::win_helpers::get_cur_username;

use log::info;

mod file;
mod hashing;
mod logging;
mod osfig_state;
mod registry;
mod scan_settings;
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
    #[cfg(windows)]
    info!("Current Running User: {}", get_cur_username());

    // Todo implement args
    // let mut options: Vec<String> = args().collect();
    // options.remove(0);
    // if options.len() == 1 {
    //     pattern = options.get(0).unwrap();
    // }
    let osfig_settings = load_osfig_settings();

    file::scan_files(&osfig_settings);
    info!("File scanning complete");

    #[cfg(windows)]
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

use crate::helpers::get_cur_username;
use crate::osfig_state::load_osfig_settings;
use log::info;

mod file;
mod hashing;
mod helpers;
mod logging;
mod osfig_state;
mod scan_settings;

#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod win_acl;

fn main() -> std::io::Result<()> {
    logging::setup_logging();

    info!(
        "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
    );
    info!("Logging setup completed");
    info!("Initializing OSFIG");
    crate::osfig_state::print_usage();
    info!("Current Running User: {}", get_cur_username());

    // Todo implement args
    // let mut options: Vec<String> = args().collect();
    // options.remove(0);
    // if options.len() == 1 {
    //     pattern = options.get(0).unwrap();
    // }
    let osfig_settings = load_osfig_settings();

    if osfig_settings.scan_settings.scan_files {
        file::scan_files(&osfig_settings);
        info!("File scanning complete");
    }

    #[cfg(windows)]
    if osfig_settings.scan_settings.scan_registry {
        registry::scan_reg_keys();
        info!("Registry scanning complete");
    }

    Ok(())
}

// Todo Store scans in local db for comparisons
// Todo Show contents diffs in verbose mode
// Todo Set up a build pipeline that automatically addresses versioning
// Todo Add commandline options

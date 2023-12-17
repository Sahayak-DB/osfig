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
mod tests;
#[cfg(windows)]
mod win_acl;

fn main() -> std::io::Result<()> {
    logging::setup_logging();

    info!(
        "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
    );
    info!("Logging setup completed");
    info!("Initializing OSFIG v{}", env!("CARGO_PKG_VERSION"));
    osfig_state::print_usage();
    info!("Current Running User: {}", get_cur_username());

    // Todo implement args
    // let mut options: Vec<String> = args().collect();
    // options.remove(0);
    // if options.len() == 1 {
    //     pattern = options.get(0).unwrap();
    // }
    let osfig_settings = load_osfig_settings();

    let mut scan_results = helpers::ScanResults::default();

    if osfig_settings.scan_settings.scan_files {
        scan_results.add_files(file::scan_files(&osfig_settings));
        info!("File scanning complete");
    } else {
        info!("File scanning disabled this run: Validate settings if this is not intended")
    }

    #[cfg(windows)]
    if osfig_settings.scan_settings.scan_registry {
        scan_results.add_registries(registry::scan_reg_keys(
            &osfig_settings.scan_settings.registry_patterns,
        ));
        info!("Registry scanning complete");
    } else {
        info!("Registry scanning disabled this run: Validate settings if this is not intended")
    }

    helpers::save_results_to_file(scan_results, &osfig_settings);

    Ok(())
}

// Todo Store scans in local db for comparisons
// Todo Set up a build pipeline that automatically addresses versioning
// Todo Add commandline options

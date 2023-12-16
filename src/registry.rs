#[cfg(windows)]
use winreg::enums::HKEY_LOCAL_MACHINE;

#[cfg(windows)]
pub fn scan_reg_keys() {
    // Testing Registry Browsing
    println!("\nRegistry--");
    let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    println!("      hklm: {:?}", hklm);
    let reg_handle = hklm.open_subkey("SOFTWARE").unwrap();
    println!("reg_handle: {:?}", reg_handle);
    let reg_handle = reg_handle.open_subkey("Python").unwrap();
    println!("reg_handle: {:?}", reg_handle);
    let reg_handle = reg_handle.open_subkey("PythonCore").unwrap();
    println!("reg_handle: {:?}", reg_handle);
    let reg_value: String = reg_handle.get_value("DisplayName").unwrap();
    println!("reg_values: {:?}", reg_value);

    // Testing Registry Direct Paths
    let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    let reg_handle = hklm.open_subkey("SOFTWARE\\Python\\PythonCore").unwrap();
    let reg_value: String = reg_handle.get_value("DisplayName").unwrap();
    println!(" reg_value: {:?}", reg_value);
    println!();

    // Testing configurable registry paths
    // HKEY_CLASSES_ROOT
    // HKEY_CURRENT_USER
    // HKEY_LOCAL_MACHINE
    // HKEY_USERS
    // HKEY_PERFORMANCE_DATA
    // HKEY_PERFORMANCE_TEXT
    // HKEY_PERFORMANCE_NLSTEXT
    // HKEY_CURRENT_CONFIG
    // HKEY_DYN_DATA
    // HKEY_CURRENT_USER_LOCAL_SETTINGS
    let root = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    // Used for showing all sub keys
    let handle = root.open_subkey("SOFTWARE\\Python\\PythonCore").unwrap();
    let sub_handles = handle.enum_keys();
    let values = handle.enum_values();

    println!("KEYS:");
    for handle in sub_handles {
        println!(
            "HKLM\\SOFTWARE\\Python\\PythonCore\\{}",
            handle.unwrap().to_string()
        );
    }

    println!("VALUES:");
    for value in values {
        let this_value = value.unwrap();
        println!(
            "HKLM\\SOFTWARE\\Python\\PythonCore\\{}|{}",
            this_value.0, this_value.1
        );
    }

    println!()
}

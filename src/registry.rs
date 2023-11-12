use winreg::enums::HKEY_LOCAL_MACHINE;

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
}

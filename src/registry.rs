use std::ops::Index;
use winreg::enums::{
    HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_CURRENT_USER_LOCAL_SETTINGS,
    HKEY_DYN_DATA, HKEY_LOCAL_MACHINE, HKEY_PERFORMANCE_DATA, HKEY_PERFORMANCE_NLSTEXT,
    HKEY_PERFORMANCE_TEXT, HKEY_USERS,
};
use winreg::{EnumKeys, EnumValues, RegKey, RegValue, HKEY};

#[cfg(windows)]
#[cfg(windows)]
pub fn get_registry_hkey(hkey_name: &str) -> Result<HKEY, String> {
    match hkey_name {
        "HKEY_CLASSES_ROOT" => Ok(HKEY_CLASSES_ROOT),
        "HKCR" => Ok(HKEY_CLASSES_ROOT),
        "HKEY_CURRENT_USER" => Ok(HKEY_CURRENT_USER),
        "HKCU" => Ok(HKEY_CURRENT_USER),
        "HKEY_LOCAL_MACHINE" => Ok(HKEY_LOCAL_MACHINE),
        "HKLM" => Ok(HKEY_LOCAL_MACHINE),
        "HKEY_USERS" => Ok(HKEY_USERS),
        "HKU" => Ok(HKEY_USERS),
        "HKEY_PERFORMANCE_DATA" => Ok(HKEY_PERFORMANCE_DATA),
        "HKEY_PERFORMANCE_TEXT" => Ok(HKEY_PERFORMANCE_TEXT),
        "HKEY_PERFORMANCE_NLSTEXT" => Ok(HKEY_PERFORMANCE_NLSTEXT),
        "HKEY_CURRENT_CONFIG" => Ok(HKEY_CURRENT_CONFIG),
        "HKCC" => Ok(HKEY_CURRENT_CONFIG),
        "HKEY_DYN_DATA" => Ok(HKEY_DYN_DATA),
        "HKEY_CURRENT_USER_LOCAL_SETTINGS" => Ok(HKEY_CURRENT_USER_LOCAL_SETTINGS),
        _ => Err("Cannot determine HKEY.".to_string()),
    }
}

#[cfg(windows)]
pub fn scan_reg_key(full_registry_path: String) {
    // Todo add the flags on key opening so we only have read access
    let mut path_items: Vec<&str>;
    if full_registry_path.contains("\\") {
        path_items = full_registry_path.split("\\").collect();
    } else if full_registry_path.contains("/") {
        path_items = full_registry_path.split("/").collect();
    } else {
        panic!("WOWSERS!")
    }

    let hkey: RegKey = match get_registry_hkey(path_items[0]) {
        Ok(hkey) => {
            path_items.remove(0);
            RegKey::predef(hkey)
        }
        Err(_) => {
            panic!("HANDLING ERRORS IS FUN!")
        }
    };

    let mut reg_path: Vec<&str> = Vec::new();
    let mut value: &str = "";
    let mut final_subkey: &str = "";

    if path_items.index(path_items.len() - 1).contains("|") {
        let temp_val: Vec<&str> = path_items.index(path_items.len() - 1).split("|").collect();
        value = temp_val[1];
        path_items.pop();
        path_items.push(temp_val[0]);
    }

    for (i, path_item) in path_items.iter().enumerate() {
        if i != path_items.len() - 1 {
            reg_path.push(path_item)
        } else if value.len() > 0 {
            reg_path.push(path_item)
        } else {
            final_subkey = path_item
        }
    }

    // Check that you never get value and final_subkey to both be populated

    // This is the majority of our path
    let final_path = reg_path.join("\\");
    let reg_handle = hkey.open_subkey(final_path).unwrap();

    // Now we must handle the final subkey, or the specific value

    println!();
    println!();
    println!("   reg_path: {}", full_registry_path);
    let mut final_handle: RegKey;
    if final_subkey.len() > 0 {
        final_handle = reg_handle.open_subkey(final_subkey).unwrap();
        let keys = final_handle.enum_keys();
        let values = final_handle.enum_values();
        for key in keys.map(|x| x.unwrap()) {
            println!(" reg_subkey: {:?}", key);
        }
        // println!("    reg_keys: {:?}", keys);
        for (name, value) in values.map(|x| x.unwrap()) {
            println!("    reg_val: {} = {}", name, value);
        }
    }

    let mut target_value: String = String::new();
    if value.len() > 0 {
        target_value = reg_handle.get_value(value).unwrap();
        println!("target_value: {:?}", target_value);
    }
}

#[cfg(windows)]
pub fn scan_reg_keys(path_list: Vec<String>) {
    for path in path_list {
        scan_reg_key(path)
    }
}

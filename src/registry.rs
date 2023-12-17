use serde::{Deserialize, Serialize};
use std::ops::Index;
use winreg::enums::{
    HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_CURRENT_USER_LOCAL_SETTINGS,
    HKEY_DYN_DATA, HKEY_LOCAL_MACHINE, HKEY_PERFORMANCE_DATA, HKEY_PERFORMANCE_NLSTEXT,
    HKEY_PERFORMANCE_TEXT, HKEY_USERS,
};
use winreg::{RegKey, HKEY};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryResult {
    path: String,
    data: RegistryData,
}

impl RegistryResult {
    pub fn add_data(&mut self, new_data: RegistryData) {
        self.data.add_data(new_data)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryData {
    keys: Vec<String>,
    values: Vec<String>,
}

impl RegistryData {
    pub fn add_data(&mut self, new_data: RegistryData) {
        for key in new_data.keys {
            self.add_key(key)
        }
        for value in new_data.values {
            self.add_value(value)
        }
    }
    pub fn add_key(&mut self, new_key: String) {
        let mut found_match = false;
        for key in self.keys.clone() {
            if key.eq(&new_key) {
                found_match = true;
            }
        }
        if !found_match {
            self.keys.push(new_key)
        }
    }

    pub fn add_value(&mut self, new_value: String) {
        let mut found_match = false;
        for value in self.values.clone() {
            if value.eq(&new_value) {
                found_match = true;
            }
        }
        if !found_match {
            self.values.push(new_value)
        }
    }
    pub fn add_value_from_pair(&mut self, target_value: String, value: String) {
        let final_data = format!("{} = {}", target_value, value);
        self.add_value(final_data)
    }
}

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
pub fn scan_reg_key(full_registry_path: &String) -> RegistryResult {
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
    let mut target_value: &str = "";
    let mut final_subkey: &str = "";

    if path_items.index(path_items.len() - 1).contains("|") {
        let temp_val: Vec<&str> = path_items.index(path_items.len() - 1).split("|").collect();
        target_value = temp_val[1];
        path_items.pop();
        path_items.push(temp_val[0]);
    }

    for (i, path_item) in path_items.iter().enumerate() {
        if i != path_items.len() - 1 {
            reg_path.push(path_item)
        } else if target_value.len() > 0 {
            reg_path.push(path_item)
        } else {
            final_subkey = path_item
        }
    }

    // Todo check that you never get value and final_subkey to both be populated

    // This is the majority of our path
    let final_path = reg_path.join("\\");
    let reg_handle = hkey.open_subkey(final_path.clone()).unwrap();

    let mut result_path: String = String::from("");
    if full_registry_path.contains("|") {
        // result_path = full_registry_path.split("|").collect()[0];

        let result_path_tmp: Vec<&str> = full_registry_path.split("|").collect();
        result_path = result_path_tmp.index(0).to_string();
    } else {
        result_path = full_registry_path.clone();
    }

    // Start constructing our output

    let mut registry_data = RegistryData {
        keys: vec![],
        values: vec![],
    };

    // Now we must handle the final subkey, or the specific value
    let mut final_handle: RegKey;
    if final_subkey.len() > 0 {
        final_handle = reg_handle.open_subkey(final_subkey).unwrap();
        let keys = final_handle.enum_keys();
        let values = final_handle.enum_values();
        for key in keys.map(|x| x.unwrap()) {
            registry_data.add_key(key)
        }
        // println!("    reg_keys: {:?}", keys);
        for (value_key, value_value) in values.map(|x| x.unwrap()) {
            registry_data.add_value_from_pair(value_key, value_value.to_string())
        }
    }

    let mut value: String = String::new();
    if target_value.len() > 0 {
        value = reg_handle.get_value(target_value).unwrap();
        registry_data.add_value_from_pair(target_value.to_string(), value)
    }
    RegistryResult {
        path: result_path.to_string(),
        data: registry_data,
    }
}

#[cfg(windows)]
pub fn scan_reg_keys(path_list: &Vec<String>) -> Vec<RegistryResult> {
    let mut registry_results = vec![];

    for path in path_list {
        let mut registry_result = RegistryResult {
            path: "".to_string(),
            data: RegistryData {
                keys: vec![],
                values: vec![],
            },
        };

        registry_results = add_registry_result(registry_results, scan_reg_key(path));
    }

    registry_results
}

pub fn add_registry_result(
    mut results: Vec<RegistryResult>,
    new_result: RegistryResult,
) -> Vec<RegistryResult> {
    let match_index = find_registry_result(&results, &new_result.path);
    match match_index {
        Some(match_index) => results = update_registry_result(results, match_index, new_result),
        None => results.push(new_result),
    }
    results
}
fn find_registry_result(results: &Vec<RegistryResult>, path: &str) -> Option<usize> {
    results.iter().position(|result| result.path == path)
}
fn update_registry_result(
    mut results: Vec<RegistryResult>,
    index: usize,
    new_result: RegistryResult,
) -> Vec<RegistryResult> {
    let mut existing_result = results.remove(index);
    existing_result.add_data(new_result.data);
    results.push(existing_result);
    results
}

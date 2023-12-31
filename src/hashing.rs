use crate::scan_settings::FileHashes;
use blake2s_simd;
use blake2s_simd::Params;
use log::{info, warn};
use sha256::try_digest;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub struct HashValues {
    pub md5: String,
    pub sha256: String,
    pub blake2s: String,
}
impl fmt::Display for HashValues {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MD5:{}, SHA256:{}, BLAKE2:{}",
            self.md5, self.sha256, self.blake2s
        )
    }
}

pub fn get_all_hashes(hash_values: &FileHashes, read_buffer_size: u64, path: &Path) -> HashValues {
    let mut hashes: HashValues = HashValues {
        md5: "".to_string(),
        sha256: "".to_string(),
        blake2s: "".to_string(),
    };

    if path.is_file() {
        if hash_values.md5 {
            hashes.md5 = get_md5(path, read_buffer_size);
        }
        if hash_values.sha256 {
            hashes.sha256 = get_sha256(path, read_buffer_size);
        }
        if hash_values.blake2s {
            hashes.blake2s = get_blake2s(path, read_buffer_size);
        }
        info!("Hashing complete");
    } else {
        // While I have no intention of supporting directory hashing at this time, I'm curious how
        // many users would have configurations that would attempt it. Putting this log here just
        // to potentially collect some insight in case I'm later asked to add dir hashing and I
        // agree to build it.
        info!("Hashing attempted on a directory: Unsupported functionality at this time");
    }

    hashes
}

pub fn get_md5(path: &Path, read_buffer_size: u64) -> String {
    // MD5 does have collissions, but it's still widely employed with commercial software
    // that users may need to compare with.
    if File::open(path).is_err() {
        warn!(
            "Cannot open file for md5 hashing: {:?}",
            path.to_str().unwrap()
        );
        return String::from("Cannot open file");
    }

    let file = File::open(path).expect("Cannot open file");
    let file_length = file.metadata().unwrap().len();

    // This buffer size will directly correlate to RAM usage. OSFIG is currently single threaded,
    // but need to keep this in mind for the distant future.
    let read_buffer_size = file_length.min(read_buffer_size) as usize;
    let mut read_buffer = BufReader::with_capacity(read_buffer_size, file);
    let mut md5_context = md5::Context::new();
    loop {
        let file_chunk = read_buffer.fill_buf().unwrap();
        // If the part is empty then we have reached EOF
        if file_chunk.is_empty() {
            break;
        }
        // Hasher needs to consume data before the buffer does
        md5_context.consume(file_chunk);
        let part_len = file_chunk.len();
        // Buffer consuming the data moves us forward in the file
        read_buffer.consume(part_len);
    }
    let md5_hash = format!("{:x}", md5_context.compute()).to_ascii_uppercase();
    md5_hash
}

pub fn get_sha256(path: &Path, _read_buffer_size: u64) -> String {
    // Todo if possible, implement a read buffer with size read_buffer_size
    if File::open(path).is_err() {
        warn!(
            "Cannot open file for sha256 hashing: {:?}",
            path.to_str().unwrap()
        );
        return String::from("Cannot open file");
    }

    let sha256_hash = try_digest(Path::new(path)).unwrap().to_ascii_uppercase();
    sha256_hash
}

pub fn get_blake2s(path: &Path, read_buffer_size: u64) -> String {
    if File::open(path).is_err() {
        warn!(
            "Cannot open file for blake2s hashing: {:?}",
            path.to_str().unwrap()
        );
        return String::from("Cannot open file");
    }

    let file = File::open(path).expect("Cannot open file");
    let file_length = file.metadata().unwrap().len();

    // This buffer size will directly correlate to RAM usage. OSFIG is currently single threaded,
    // but need to keep this in mind for the distant future.
    let read_buffer_size = file_length.min(read_buffer_size) as usize;
    let mut read_buffer = BufReader::with_capacity(read_buffer_size, file);
    let mut hasher = Params::new().to_state();

    loop {
        let part = read_buffer.fill_buf().unwrap();
        // If the part is empty then we have reached EOF
        if part.is_empty() {
            break;
        }
        // Hasher needs to consume data before the buffer does
        hasher.update(part);
        let part_len = part.len();
        // Buffer consuming the data moves us forward in the file
        read_buffer.consume(part_len);
    }
    let result = hasher.finalize().to_hex();
    let blake2_hash = result.to_ascii_uppercase();

    blake2_hash
}

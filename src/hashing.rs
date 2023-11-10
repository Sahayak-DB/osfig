use std::fmt;
use sha256::try_digest;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use log::info;
use blake2s_simd;
use blake2s_simd::Params;

pub struct HashValues {
    // Is there a real need to add 128 or 512 or others like Blake2?
    pub md5: String,
    pub sha256: String,
    pub blake2s: String
}
impl fmt::Display for HashValues {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MD5:{}, SHA256:{}, BLAKE2:{}", self.md5, self.sha256, self.blake2s)
    }
}

pub fn get_all_hashes(path: &Path) -> HashValues {
    let hashes: HashValues = HashValues{
        md5: get_md5(path),
        sha256: get_sha256(path),
        blake2s: get_blake2s(path),
    };
    hashes
}
pub fn get_md5(path: &Path) -> String {
    // MD5 does have collissions, but it's still widely employed with commercial software
    // that users may need to compare with.
    if File::open(path).is_err() {
        info!("Cannot open file for hashing: {:?}", path.to_str());
        return String::from("Cannot open file.");
    }

    let file = File::open(path).expect("Cannot open file");
    let len = file.metadata().unwrap().len();

    // Todo Need more testing on buffer size for reading large files. 4k seems to perform adequately
    // This buffer size will directly correlate to RAM usage. OSFIG is currently single threaded,
    // but need to keep this in mind for the distant future.
    let buf_len = len.min(4_000) as usize;
    let mut buf = BufReader::with_capacity(buf_len, file);
    let mut ctx = md5::Context::new();
    loop {
        let part = buf.fill_buf().unwrap();
        // If the part is empty then we have reached EOF
        if part.is_empty() {
            break;
        }
        // Hasher needs to consume data before the buffer does
        ctx.consume(part);
        let part_len = part.len();
        // Buffer consuming the data moves us forward in the file
        buf.consume(part_len);
    }
    let md5_hash = format!("{:x}", ctx.compute()).to_ascii_uppercase();
    md5_hash
}

pub fn get_sha256(path: &Path) -> String {
    if File::open(path).is_err() {
        info!("Cannot open file for hashing: {:?}", path.to_str());
        return String::from("Cannot open file.");
    }

    let sha256_hash = try_digest(Path::new(path)).unwrap().to_ascii_uppercase();
    sha256_hash
}

pub fn get_blake2s(path: &Path) -> String {
    if File::open(path).is_err() {
        info!("Cannot open file for hashing: {:?}", path.to_str());
        return String::from("Cannot open file.");
    }

    let file = File::open(path).expect("Cannot open file");
    let len = file.metadata().unwrap().len();

    // Todo Need more testing on buffer size for reading large files. 4k seems to perform adequately
    // This buffer size will directly correlate to RAM usage. OSFIG is currently single threaded,
    // but need to keep this in mind for the distant future.
    let buf_len = len.min(4_000) as usize;
    let mut buf = BufReader::with_capacity(buf_len, file);
    let mut hasher = Params::new().to_state();

    loop {
        let part = buf.fill_buf().unwrap();
        // If the part is empty then we have reached EOF
        if part.is_empty() {
            break;
        }
        // Hasher needs to consume data before the buffer does
        hasher.update(part);
        let part_len = part.len();
        // Buffer consuming the data moves us forward in the file
        buf.consume(part_len);
    }
    let result = hasher.finalize().to_hex();
    let blake2_hash = result.to_ascii_uppercase();

    blake2_hash

}
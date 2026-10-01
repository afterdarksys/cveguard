//! Toolchain seal. Digests are compared in constant time.
//!
//! Threats: a replaced afterguard, nocved, or aftercve binary should stop
//! enforcement. A symlink, a writable file, a bad owner, or a digest of the
//! wrong length is a mismatch. The seal file itself is mode 0600.

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Error, invalid, schema};
use crate::fs::{self, FilePolicy};
use crate::model::{MAX_SEAL_ENTRIES, MAX_SEAL_FILE, SCHEMA_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealStatus {
    Missing,
    Valid,
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealEntry {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u16,
    pub entries: Vec<SealEntry>,
}

pub fn verify(path: &Path) -> SealStatus {
    let bytes = match fs::read_trusted(path, 1024 * 1024, FilePolicy::Secret0600) {
        Ok(bytes) => bytes,
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return SealStatus::Missing;
        }
        Err(_) => return SealStatus::Mismatch,
    };
    let manifest: Manifest = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(_) => return SealStatus::Mismatch,
    };
    if manifest.schema_version != SCHEMA_VERSION || manifest.entries.len() > MAX_SEAL_ENTRIES {
        return SealStatus::Mismatch;
    }
    for entry in &manifest.entries {
        let Ok(expected) = decode_digest(&entry.sha256) else {
            return SealStatus::Mismatch;
        };
        let Ok(actual) = hash_file(Path::new(&entry.path)) else {
            return SealStatus::Mismatch;
        };
        if expected.ct_eq(&actual).unwrap_u8() != 1 {
            return SealStatus::Mismatch;
        }
    }
    SealStatus::Valid
}

fn decode_digest(hex_text: &str) -> Result<[u8; 32], Error> {
    if hex_text.len() != 64 || !hex_text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("digest rejected"));
    }
    let raw = hex::decode(hex_text).map_err(|_| invalid("digest rejected"))?;
    if raw.len() != 32 {
        return Err(invalid("digest rejected"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub fn hash_file(path: &Path) -> Result<[u8; 32], Error> {
    let pre = std::fs::symlink_metadata(path)?;
    if pre.file_type().is_symlink() {
        return Err(invalid("symlink rejected"));
    }
    let mut file = fs::open_nofollow(path)?;
    let md = file.metadata()?;
    fs::check_metadata(&md, FilePolicy::Config)?;
    if md.len() > u64::try_from(MAX_SEAL_FILE).unwrap_or(u64::MAX) {
        return Err(invalid("file too large"));
    }
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut chunk = [0u8; 8192];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if total > u64::try_from(MAX_SEAL_FILE).unwrap_or(u64::MAX) {
            return Err(invalid("file too large"));
        }
        hasher.update(&chunk[..n]);
    }
    let finished = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&finished);
    Ok(out)
}

pub fn pin(paths: &[std::path::PathBuf]) -> Result<Manifest, Error> {
    if paths.len() > MAX_SEAL_ENTRIES {
        return Err(invalid("too many seal entries"));
    }
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let digest = hash_file(path)?;
        let text = path.to_str().ok_or_else(|| invalid("path rejected"))?;
        entries.push(SealEntry {
            path: text.to_owned(),
            sha256: hex::encode(digest),
        });
    }
    Ok(Manifest {
        schema_version: SCHEMA_VERSION,
        entries,
    })
}

pub fn write_manifest(path: &Path, manifest: &Manifest) -> Result<(), Error> {
    if manifest.entries.len() > MAX_SEAL_ENTRIES || manifest.schema_version != SCHEMA_VERSION {
        return Err(invalid("seal rejected"));
    }
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|_| schema("json rejected"))?;
    fs::write_atomic_0600(path, &bytes)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn missing_symlink_tamper_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        assert_eq!(verify(&missing), SealStatus::Missing);

        let file = dir.path().join("tool");
        std::fs::write(&file, b"alpha").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let manifest = pin(std::slice::from_ref(&file)).unwrap();
        let seal = dir.path().join("seal.json");
        write_manifest(&seal, &manifest).unwrap();
        assert_eq!(verify(&seal), SealStatus::Valid);

        std::fs::write(&file, b"beta").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(verify(&seal), SealStatus::Mismatch);

        std::fs::write(&file, b"alpha").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(verify(&seal), SealStatus::Valid);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(verify(&seal), SealStatus::Mismatch);

        let link = dir.path().join("seal-link");
        std::os::unix::fs::symlink(&seal, &link).unwrap();
        assert_eq!(verify(&link), SealStatus::Mismatch);

        std::fs::set_permissions(&seal, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(verify(&seal), SealStatus::Mismatch);
    }

    #[test]
    fn too_many_entries_and_bad_hex_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tool");
        std::fs::write(&file, b"alpha").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let one = pin(std::slice::from_ref(&file)).unwrap();
        let mut many = one.clone();
        many.entries = vec![one.entries[0].clone(); MAX_SEAL_ENTRIES + 1];
        let seal = dir.path().join("seal.json");
        let bytes = serde_json::to_vec(&many).unwrap();
        fs::write_atomic_0600(&seal, &bytes).unwrap();
        assert_eq!(verify(&seal), SealStatus::Mismatch);

        let mut bad = one;
        bad.entries[0].sha256 = "zz".into();
        write_manifest(&seal, &bad).unwrap();
        assert_eq!(verify(&seal), SealStatus::Mismatch);
    }
}

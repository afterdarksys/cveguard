//! Toolchain seal. Digests are compared in constant time.
//!
//! Threats: a replaced afterguard, nocved, or aftercve binary should stop
//! enforcement. A symlink, a writable file, a bad owner, a digest of the
//! wrong length, a relative or non-canonical path, an empty manifest, or a
//! manifest that does not cover all six census binaries is a mismatch. The
//! seal file itself is mode 0600. The verified files (canonical path plus
//! dev/ino of the hashed fd) are the only identities the engine treats as
//! protected; a basename or `comm` never is.
//!
//! Not covered: the manifest is not signed. An attacker who can rewrite the
//! 0600 seal file as its owner can re-pin a replaced binary. Offline Ed25519
//! signing is future work (DESIGN.md).

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Error, invalid, schema};
use crate::fs::{self, FilePolicy};
use crate::model::{MAX_SEAL_ENTRIES, MAX_SEAL_FILE, SCHEMA_VERSION, basename};

/// The six toolchain binaries a manifest must cover.
pub const CENSUS: [&str; 6] = [
    "nocved",
    "nocve-store",
    "aftercve",
    "afterguard",
    "afteralert",
    "afterseal",
];

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

/// Files whose digest verified, keyed by canonical path, with the dev/ino of
/// the file that was hashed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sealed {
    files: HashMap<String, (u64, u64)>,
}

impl Sealed {
    /// True only when `exe` is exactly a verified canonical path and the file
    /// at that path now has the same dev/ino that was hashed. A symlink, a
    /// missing file, or a replaced inode is not protected.
    #[must_use]
    pub fn protects(&self, exe: &str) -> bool {
        let Some(&(dev, ino)) = self.files.get(exe) else {
            return false;
        };
        match std::fs::symlink_metadata(exe) {
            Ok(md) if md.file_type().is_file() => md.dev() == dev && md.ino() == ino,
            _ => false,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Seal status plus the verified identities. `sealed` is empty unless the
/// status is `Valid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealCheck {
    pub status: SealStatus,
    pub sealed: Sealed,
}

impl SealCheck {
    #[must_use]
    pub fn of(status: SealStatus) -> Self {
        Self {
            status,
            sealed: Sealed::default(),
        }
    }
}

/// Reads and shape-checks a manifest. `Err` carries the status to report.
pub fn load_manifest(path: &Path) -> Result<Manifest, SealStatus> {
    let bytes = match fs::read_trusted(path, 1024 * 1024, FilePolicy::Secret0600) {
        Ok(bytes) => bytes,
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SealStatus::Missing);
        }
        Err(_) => return Err(SealStatus::Mismatch),
    };
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| SealStatus::Mismatch)?;
    if manifest.schema_version != SCHEMA_VERSION || manifest_shape(&manifest).is_err() {
        return Err(SealStatus::Mismatch);
    }
    Ok(manifest)
}

/// Non-empty, at most `MAX_SEAL_ENTRIES`, absolute paths, all six census
/// basenames present.
fn manifest_shape(manifest: &Manifest) -> Result<(), Error> {
    if manifest.entries.is_empty() {
        return Err(invalid("empty seal rejected"));
    }
    if manifest.entries.len() > MAX_SEAL_ENTRIES {
        return Err(invalid("too many seal entries"));
    }
    if manifest
        .entries
        .iter()
        .any(|e| !Path::new(&e.path).is_absolute())
    {
        return Err(invalid("seal path rejected"));
    }
    let names: HashSet<&str> = manifest.entries.iter().map(|e| basename(&e.path)).collect();
    if CENSUS.iter().any(|name| !names.contains(name)) {
        return Err(invalid("seal must cover the six census binaries"));
    }
    Ok(())
}

/// Hashes one entry and compares in constant time. Returns the dev/ino of
/// the hashed file. The path must already be canonical.
pub fn check_entry(entry: &SealEntry) -> Result<(u64, u64), Error> {
    let expected = decode_digest(&entry.sha256)?;
    let path = Path::new(&entry.path);
    let canonical = std::fs::canonicalize(path)?;
    if canonical.as_os_str() != path.as_os_str() {
        return Err(invalid("seal path not canonical"));
    }
    let (actual, dev, ino) = hash_file_identity(path)?;
    if expected.ct_eq(&actual).unwrap_u8() != 1 {
        return Err(invalid("digest mismatch"));
    }
    Ok((dev, ino))
}

#[must_use]
pub fn check(path: &Path) -> SealCheck {
    let manifest = match load_manifest(path) {
        Ok(m) => m,
        Err(status) => return SealCheck::of(status),
    };
    let mut files = HashMap::new();
    for entry in &manifest.entries {
        match check_entry(entry) {
            Ok(id) => {
                files.insert(entry.path.clone(), id);
            }
            Err(_) => return SealCheck::of(SealStatus::Mismatch),
        }
    }
    SealCheck {
        status: SealStatus::Valid,
        sealed: Sealed { files },
    }
}

#[must_use]
pub fn verify(path: &Path) -> SealStatus {
    check(path).status
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
    hash_file_identity(path).map(|(digest, _, _)| digest)
}

/// SHA-256 of a regular file opened with O_NOFOLLOW, plus the dev/ino of the
/// fd that was read.
pub fn hash_file_identity(path: &Path) -> Result<([u8; 32], u64, u64), Error> {
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
    Ok((out, md.dev(), md.ino()))
}

/// Pins canonical paths. Refuses an empty list and a list that does not
/// cover the six census binaries, so `pin` cannot write a seal `verify`
/// would reject.
pub fn pin(paths: &[std::path::PathBuf]) -> Result<Manifest, Error> {
    if paths.len() > MAX_SEAL_ENTRIES {
        return Err(invalid("too many seal entries"));
    }
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let canonical = std::fs::canonicalize(path)?;
        let digest = hash_file(&canonical)?;
        let text = canonical.to_str().ok_or_else(|| invalid("path rejected"))?;
        entries.push(SealEntry {
            path: text.to_owned(),
            sha256: hex::encode(digest),
        });
    }
    let manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        entries,
    };
    manifest_shape(&manifest)?;
    Ok(manifest)
}

pub fn write_manifest(path: &Path, manifest: &Manifest) -> Result<(), Error> {
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(invalid("seal rejected"));
    }
    manifest_shape(manifest)?;
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|_| schema("json rejected"))?;
    fs::write_atomic_0600(path, &bytes)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    fn toolchain(dir: &Path) -> Vec<PathBuf> {
        let dir = std::fs::canonicalize(dir).unwrap();
        CENSUS
            .iter()
            .map(|name| {
                let path = dir.join(name);
                std::fs::write(&path, name.as_bytes()).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
                path
            })
            .collect()
    }

    fn raw_seal(path: &Path, manifest: &Manifest) {
        fs::write_atomic_0600(path, &serde_json::to_vec(manifest).unwrap()).unwrap();
    }

    #[test]
    fn missing_symlink_tamper_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        assert_eq!(verify(&missing), SealStatus::Missing);

        let files = toolchain(dir.path());
        let file = files[0].clone();
        let manifest = pin(&files).unwrap();
        let seal = dir.path().join("seal.json");
        write_manifest(&seal, &manifest).unwrap();
        assert_eq!(verify(&seal), SealStatus::Valid);

        std::fs::write(&file, b"beta").unwrap();
        assert_eq!(verify(&seal), SealStatus::Mismatch);

        std::fs::write(&file, CENSUS[0].as_bytes()).unwrap();
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
        let files = toolchain(dir.path());
        let one = pin(&files).unwrap();
        let mut many = one.clone();
        many.entries = vec![one.entries[0].clone(); MAX_SEAL_ENTRIES + 1];
        let seal = dir.path().join("seal.json");
        raw_seal(&seal, &many);
        assert_eq!(verify(&seal), SealStatus::Mismatch);

        let mut bad = one;
        bad.entries[0].sha256 = "zz".into();
        write_manifest(&seal, &bad).unwrap();
        assert_eq!(verify(&seal), SealStatus::Mismatch);
    }

    #[test]
    fn empty_manifest_is_mismatch_and_cannot_be_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let seal = dir.path().join("seal.json");
        let empty = Manifest {
            schema_version: SCHEMA_VERSION,
            entries: Vec::new(),
        };
        raw_seal(&seal, &empty);
        assert_eq!(verify(&seal), SealStatus::Mismatch);
        assert!(pin(&[]).is_err());
        assert!(write_manifest(&seal, &empty).is_err());
    }

    #[test]
    fn manifest_must_cover_all_six_census_binaries() {
        let dir = tempfile::tempdir().unwrap();
        let files = toolchain(dir.path());
        let full = pin(&files).unwrap();
        for (skip, name) in CENSUS.iter().enumerate() {
            let mut partial = full.clone();
            partial.entries.remove(skip);
            let seal = dir.path().join(format!("seal-{skip}.json"));
            raw_seal(&seal, &partial);
            assert_eq!(verify(&seal), SealStatus::Mismatch, "{name}");
        }
        assert!(pin(&files[..5]).is_err());
    }

    #[test]
    fn missing_sealed_path_is_mismatch_not_missing() {
        let dir = tempfile::tempdir().unwrap();
        let files = toolchain(dir.path());
        let seal = dir.path().join("seal.json");
        write_manifest(&seal, &pin(&files).unwrap()).unwrap();
        std::fs::remove_file(&files[2]).unwrap();
        assert_eq!(verify(&seal), SealStatus::Mismatch);
    }

    #[test]
    fn relative_or_non_canonical_paths_are_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let files = toolchain(dir.path());
        let seal = dir.path().join("seal.json");
        let mut manifest = pin(&files).unwrap();
        manifest.entries[0].path = "nocved".into();
        raw_seal(&seal, &manifest);
        assert_eq!(verify(&seal), SealStatus::Mismatch);

        let mut manifest = pin(&files).unwrap();
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        manifest.entries[0].path = format!("{}/./nocved", canonical.display());
        raw_seal(&seal, &manifest);
        assert_eq!(verify(&seal), SealStatus::Mismatch);
    }

    #[test]
    fn sealed_protects_only_the_verified_identity() {
        let dir = tempfile::tempdir().unwrap();
        let files = toolchain(dir.path());
        let seal = dir.path().join("seal.json");
        write_manifest(&seal, &pin(&files).unwrap()).unwrap();
        let checked = check(&seal);
        assert_eq!(checked.status, SealStatus::Valid);
        assert_eq!(checked.sealed.len(), 6);
        let real = files[5].to_str().unwrap();
        assert!(checked.sealed.protects(real));
        assert!(!checked.sealed.protects("/tmp/.x/afterseal"));
        assert!(!checked.sealed.protects("afterseal"));

        let link = dir.path().join("link-afterseal");
        std::os::unix::fs::symlink(&files[5], &link).unwrap();
        assert!(!checked.sealed.protects(link.to_str().unwrap()));

        // Same bytes, new inode: no longer the file that was hashed.
        let staged = dir.path().join("staged");
        std::fs::write(&staged, b"afterseal").unwrap();
        std::fs::rename(&staged, &files[5]).unwrap();
        assert!(!checked.sealed.protects(real));

        let missing = check(&dir.path().join("none.json"));
        assert_eq!(missing.status, SealStatus::Missing);
        assert!(missing.sealed.is_empty());
    }
}

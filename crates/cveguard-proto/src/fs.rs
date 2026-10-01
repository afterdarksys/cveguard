//! O_NOFOLLOW reads and atomic 0600 writes.
//!
//! Threats: a symlink planted between a check and a read would leak or
//! replace a seal, a ledger, or a rule file. Opens use O_NOFOLLOW, then the
//! fd is checked. Group/other write is rejected. Seal and ledger files must
//! be mode 0600. A failed write removes its temp file and returns that error.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::error::{Error, invalid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePolicy {
    /// No group/other write. Owner is root or the current user.
    Config,
    /// Mode exactly 0600. Owner is root or the current user.
    Secret0600,
}

pub fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// Effective uid from the kernel. Never inferred from `$HOME` or procfs.
#[must_use]
pub fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub fn read_trusted(path: &Path, max: usize, policy: FilePolicy) -> Result<Vec<u8>, Error> {
    let pre = std::fs::symlink_metadata(path)?;
    if pre.file_type().is_symlink() {
        return Err(invalid("symlink rejected"));
    }
    let file = open_nofollow(path)?;
    let md = file.metadata()?;
    check_metadata(&md, policy)?;
    read_limited(file, max)
}

pub fn check_metadata(md: &std::fs::Metadata, policy: FilePolicy) -> Result<(), Error> {
    if !md.is_file() {
        return Err(invalid("not a regular file"));
    }
    let owner = md.uid();
    if owner != 0 && owner != current_uid() {
        return Err(invalid("owner rejected"));
    }
    let mode = md.permissions().mode() & 0o777;
    match policy {
        FilePolicy::Config if mode & 0o022 != 0 => return Err(invalid("mode rejected")),
        FilePolicy::Secret0600 if mode != 0o600 => return Err(invalid("mode rejected")),
        _ => {}
    }
    Ok(())
}

fn read_limited(mut file: File, max: usize) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > max {
            return Err(invalid("file too large"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    let file = File::open(dir)?;
    match file.sync_all() {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(()),
        Err(e) if e.raw_os_error() == Some(22) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Writes `bytes` to `path` atomically with mode 0600.
/// Refuses an existing symlink. On a failed write, the temp file is removed
/// and either the original error or the cleanup error is returned.
pub fn write_atomic_0600(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Ok(md) = std::fs::symlink_metadata(path)
        && md.file_type().is_symlink()
    {
        return Err(invalid("symlink rejected"));
    }
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| invalid("path rejected"))?;
    let mut rnd = [0u8; 6];
    getrandom::fill(&mut rnd).map_err(|e| io::Error::other(e.to_string()))?;
    let tmp = dir.join(format!(".{name}.new-{}", hex::encode(rnd)));
    let write_result = (|| -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        fsync_dir(dir)?;
        Ok(())
    })();
    if let Err(e) = write_result {
        match std::fs::remove_file(&tmp) {
            Ok(()) => Err(e),
            Err(cleanup) if cleanup.kind() == io::ErrorKind::NotFound => Err(e),
            Err(cleanup) => Err(Error::Io(cleanup)),
        }
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn rejects_symlink_open_mode_and_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.json");
        write_atomic_0600(&path, b"{\"a\":1}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_trusted(&path, 100, FilePolicy::Config).unwrap(),
            b"{\"a\":1}"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_trusted(&path, 4, FilePolicy::Secret0600).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_trusted(&path, 100, FilePolicy::Config).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_trusted(&link, 100, FilePolicy::Config).is_err());
        assert!(write_atomic_0600(&link, b"nope").is_err());
    }

    #[test]
    fn atomic_write_is_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_atomic_0600(&path, b"{}").unwrap();
        write_atomic_0600(&path, b"{\"a\":1}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":1}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn current_uid_ignores_home_owner() {
        // Re-run this test in a child with HOME=/ (owned by root). The old
        // $HOME-owner fallback reported uid 0 there on hosts without procfs.
        if std::env::var_os("CVEGUARD_UID_PROBE").is_some() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("owned");
            std::fs::write(&path, b"x").unwrap();
            let owner = std::fs::metadata(&path).unwrap().uid();
            assert_eq!(current_uid(), owner);
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(exe)
            .args([
                "--exact",
                "fs::tests::current_uid_ignores_home_owner",
                "--quiet",
            ])
            .env("CVEGUARD_UID_PROBE", "1")
            .env("HOME", "/")
            .status()
            .unwrap();
        assert!(status.success());
    }
}

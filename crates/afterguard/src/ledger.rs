//! Append-only decision ledger. Mode 0600. A failed write rolls the length back.
//!
//! Threats: a world-readable ledger leaks decisions. A short write left in
//! place would corrupt the next parse. Symlinks are refused. Existing files
//! with the wrong mode are not chmodded into compliance.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use cveguard_proto::Error;
use cveguard_proto::fs::{self, FilePolicy};
use cveguard_proto::model::Decision;

pub fn append_decision(path: &Path, decision: &Decision, max: usize) -> Result<(), Error> {
    if max < 64 {
        return Err(Error::Invalid("ledger full".to_owned()));
    }
    let mut bytes =
        serde_json::to_vec(decision).map_err(|_| Error::Schema("json rejected".to_owned()))?;
    bytes.push(b'\n');
    if bytes.len() > max {
        return Err(Error::Invalid("ledger full".to_owned()));
    }
    let existed = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(Error::Invalid("symlink rejected".to_owned()));
        }
        Ok(_) => true,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => return Err(err.into()),
    };
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let created = !existed;
    if created && let Err(err) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        return Err(remove_if_created(path, true, Error::Io(err)));
    }
    if let Err(err) = checked(&file) {
        return Err(remove_if_created(path, created, err));
    }
    let prior = file.metadata()?.len();
    let prior_usize =
        usize::try_from(prior).map_err(|_| Error::Invalid("ledger full".to_owned()))?;
    if prior_usize.saturating_add(bytes.len()) > max {
        return Err(remove_if_created(
            path,
            created,
            Error::Invalid("ledger full".to_owned()),
        ));
    }
    if let Err(err) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        if let Err(rollback) = file.set_len(prior) {
            return Err(Error::Io(rollback));
        }
        return Err(Error::Io(err));
    }
    Ok(())
}

fn checked(file: &File) -> Result<(), Error> {
    let meta = file.metadata()?;
    fs::check_metadata(&meta, FilePolicy::Secret0600)
}

fn remove_if_created(path: &Path, created: bool, original: Error) -> Error {
    if !created {
        return original;
    }
    match std::fs::remove_file(path) {
        Ok(()) => original,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => original,
        Err(err) => Error::Io(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cveguard_proto::{Action, Origin, Outcome, Reason, SCHEMA_VERSION};
    use std::os::unix::fs::PermissionsExt;

    fn sample() -> Decision {
        Decision {
            schema_version: SCHEMA_VERSION,
            observed_at_ms: 1,
            action: Action::Alert,
            outcome: Outcome::Shadow,
            reason: Reason::PolicyShadow,
            origin: Origin::Nocved,
            plan: None,
            pid: None,
            rule_id: Some("miner-exe".to_owned()),
            cve: None,
            subject: Some("xmrig".to_owned()),
            ancestors: Vec::new(),
        }
    }

    #[test]
    fn append_is_0600_and_cap_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let decision = sample();
        append_decision(&path, &decision, 1024 * 1024).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let len = usize::try_from(std::fs::metadata(&path).unwrap().len()).unwrap();
        assert!(len >= 64);
        let err = append_decision(&path, &decision, len).unwrap_err();
        assert!(err.to_string().contains("ledger full"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            u64::try_from(len).unwrap()
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let err = append_decision(&link, &decision, 1024 * 1024).unwrap_err();
        assert!(err.to_string().contains("symlink rejected"));
    }

    #[test]
    fn existing_bad_mode_is_not_chmodded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = append_decision(&path, &sample(), 4096).unwrap_err();
        assert!(err.to_string().contains("mode rejected"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}

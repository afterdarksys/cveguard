//! `afterseal` commands. Pin refuses an empty path list.
//!
//! Threats: a second `--out` would leave the operator unsure which manifest
//! was written. Verify prints only the status word.

use std::path::{Path, PathBuf};

use cveguard_proto::Error;
use cveguard_proto::model::MAX_SEAL_ENTRIES;
use cveguard_proto::seal::{self, SealStatus};

use crate::toolchain_names;

pub const VERSION: &str = "afterseal 0.1.0";

pub fn dispatch(args: &[String]) -> Result<i32, Error> {
    match args.first().map(String::as_str) {
        Some("version") if args.len() == 1 => {
            println!("{VERSION}");
            Ok(0)
        }
        Some("census") if args.len() == 1 => {
            for name in toolchain_names() {
                println!("{name}");
            }
            Ok(0)
        }
        Some("pin") => pin_cmd(&args[1..]),
        Some("verify") => verify_cmd(&args[1..]),
        _ => Err(usage()),
    }
}

fn pin_cmd(args: &[String]) -> Result<i32, Error> {
    let mut out: Option<&str> = None;
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        let key = args[index].as_str();
        let Some(value) = args.get(index + 1) else {
            return Err(usage());
        };
        if value.starts_with('-') {
            return Err(usage());
        }
        match key {
            "--out" if out.is_none() => out = Some(value.as_str()),
            "--path" => paths.push(PathBuf::from(value)),
            _ => return Err(usage()),
        }
        index += 2;
    }
    let out = out.ok_or_else(usage)?;
    if paths.is_empty() {
        return Err(Error::Invalid("path required".to_owned()));
    }
    if paths.len() > MAX_SEAL_ENTRIES {
        return Err(Error::Invalid("too many seal entries".to_owned()));
    }
    let manifest = seal::pin(&paths)?;
    seal::write_manifest(Path::new(out), &manifest)?;
    Ok(0)
}

fn verify_cmd(args: &[String]) -> Result<i32, Error> {
    if args.len() != 2 || args[0] != "--seal" || args[1].starts_with('-') {
        return Err(usage());
    }
    let status = seal::verify(Path::new(&args[1]));
    println!("{}", status_word(status));
    Ok(status_code(status))
}

fn status_word(status: SealStatus) -> &'static str {
    match status {
        SealStatus::Valid => "valid",
        SealStatus::Missing => "missing",
        SealStatus::Mismatch => "mismatch",
    }
}

fn status_code(status: SealStatus) -> i32 {
    match status {
        SealStatus::Valid => 0,
        SealStatus::Missing | SealStatus::Mismatch => 3,
    }
}

fn usage() -> Error {
    Error::Invalid("usage".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cveguard_proto::model::is_toolchain_basename;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn pin_verify_and_census() {
        assert_eq!(VERSION, "afterseal 0.1.0");
        assert_eq!(dispatch(&["version".to_owned()]).unwrap(), 0);
        let names = toolchain_names();
        assert_eq!(names.len(), 6);
        for name in names {
            assert!(is_toolchain_basename(name), "{name}");
        }
        assert!(!is_toolchain_basename("xmrig"));
        assert_eq!(dispatch(&["census".to_owned()]).unwrap(), 0);

        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("afterguard");
        std::fs::write(&tool, b"alpha").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o644)).unwrap();
        let seal = dir.path().join("seal.json");
        let seal_text = seal.to_str().unwrap().to_owned();
        let tool_text = tool.to_str().unwrap().to_owned();
        assert_eq!(
            dispatch(&[
                "pin".to_owned(),
                "--out".to_owned(),
                seal_text.clone(),
                "--path".to_owned(),
                tool_text,
            ])
            .unwrap(),
            0
        );
        assert_eq!(
            dispatch(&["verify".to_owned(), "--seal".to_owned(), seal_text.clone()]).unwrap(),
            0
        );
        std::fs::write(&tool, b"beta").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            dispatch(&["verify".to_owned(), "--seal".to_owned(), seal_text.clone()]).unwrap(),
            3
        );
        let missing = dir.path().join("missing.json");
        assert_eq!(
            dispatch(&[
                "verify".to_owned(),
                "--seal".to_owned(),
                missing.to_str().unwrap().to_owned(),
            ])
            .unwrap(),
            3
        );
        assert!(dispatch(&["pin".to_owned(), "--out".to_owned(), seal_text.clone()]).is_err());
        assert!(
            dispatch(&[
                "pin".to_owned(),
                "--out".to_owned(),
                seal_text.clone(),
                "--out".to_owned(),
                dir.path().join("other.json").to_str().unwrap().to_owned(),
                "--path".to_owned(),
                tool.to_str().unwrap().to_owned(),
            ])
            .is_err()
        );
        assert_eq!(status_word(SealStatus::Valid), "valid");
        assert_eq!(status_word(SealStatus::Missing), "missing");
        assert_eq!(status_word(SealStatus::Mismatch), "mismatch");
    }
}

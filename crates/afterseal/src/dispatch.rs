//! `afterseal` commands. Pin refuses an empty path list and a list that
//! does not cover the six census binaries.
//!
//! Threats: a second `--out` would leave the operator unsure which manifest
//! was written. Verify and census print only status words (or the JSON
//! `status` / `reason` object darksignal reads), never file contents.

use std::path::{Path, PathBuf};

use cveguard_proto::Error;
use cveguard_proto::model::{MAX_SEAL_ENTRIES, basename};
use cveguard_proto::seal::{self, SealStatus};

use crate::toolchain_names;

pub const VERSION: &str = "afterseal 0.1.0";

pub fn dispatch(args: &[String]) -> Result<i32, Error> {
    match args.first().map(String::as_str) {
        Some("version") if args.len() == 1 => {
            println!("{VERSION}");
            Ok(0)
        }
        Some("census") => {
            let (seal_path, json) = seal_args(&args[1..])?;
            let (text, code) = census_report(Path::new(seal_path), json);
            print!("{text}");
            Ok(code)
        }
        Some("pin") => pin_cmd(&args[1..]),
        Some("verify") => {
            let (seal_path, json) = seal_args(&args[1..])?;
            let (text, code) = verify_report(Path::new(seal_path), json);
            print!("{text}");
            Ok(code)
        }
        _ => Err(usage()),
    }
}

/// `--seal PATH [--json]` in either order.
fn seal_args(args: &[String]) -> Result<(&str, bool), Error> {
    match args {
        [flag, path] if flag == "--seal" && !path.starts_with('-') => Ok((path, false)),
        [flag, path, json] | [json, flag, path]
            if flag == "--seal" && json == "--json" && !path.starts_with('-') =>
        {
            Ok((path, true))
        }
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

fn reason(status: SealStatus) -> &'static str {
    match status {
        SealStatus::Valid => "sealed",
        SealStatus::Missing => "seal_missing",
        SealStatus::Mismatch => "seal_mismatch",
    }
}

fn verify_report(path: &Path, json: bool) -> (String, i32) {
    let status = seal::verify(path);
    let text = if json {
        format!(
            "{}\n",
            serde_json::json!({"status": status_word(status), "reason": reason(status)})
        )
    } else {
        format!("{}\n", status_word(status))
    };
    (text, status_code(status))
}

/// Inspects each census binary named in the manifest: hashes the file and
/// compares it with the pinned digest. A census name with no entry is
/// `missing`; a bad file is `mismatch`. Overall status is the worst one.
fn census_report(path: &Path, json: bool) -> (String, i32) {
    let names = toolchain_names();
    let mut per: Vec<(&str, SealStatus)> = Vec::with_capacity(names.len());
    let overall = match seal::load_manifest(path) {
        Err(status) => {
            per.extend(names.iter().map(|name| (*name, status)));
            status
        }
        Ok(manifest) => {
            for name in names {
                let mut entries = manifest
                    .entries
                    .iter()
                    .filter(|e| basename(&e.path) == *name)
                    .peekable();
                let status = if entries.peek().is_none() {
                    SealStatus::Missing
                } else if entries.all(|e| seal::check_entry(e).is_ok()) {
                    SealStatus::Valid
                } else {
                    SealStatus::Mismatch
                };
                per.push((name, status));
            }
            if per.iter().any(|(_, s)| *s == SealStatus::Mismatch) {
                SealStatus::Mismatch
            } else if per.iter().any(|(_, s)| *s == SealStatus::Missing) {
                SealStatus::Missing
            } else {
                SealStatus::Valid
            }
        }
    };
    let text = if json {
        let binaries: Vec<serde_json::Value> = per
            .iter()
            .map(|(name, s)| serde_json::json!({"name": name, "status": status_word(*s)}))
            .collect();
        format!(
            "{}\n",
            serde_json::json!({
                "status": status_word(overall),
                "reason": reason(overall),
                "binaries": binaries,
            })
        )
    } else {
        per.iter()
            .map(|(name, s)| format!("{name} {}\n", status_word(*s)))
            .collect()
    };
    (text, status_code(overall))
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

    fn s(v: &str) -> String {
        v.to_owned()
    }

    /// Six toolchain files in a canonical temp dir.
    fn tools(dir: &Path) -> Vec<PathBuf> {
        let root = std::fs::canonicalize(dir).unwrap();
        toolchain_names()
            .iter()
            .map(|name| {
                let path = root.join(name);
                std::fs::write(&path, name.as_bytes()).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
                path
            })
            .collect()
    }

    fn pin_args(seal: &Path, paths: &[PathBuf]) -> Vec<String> {
        let mut args = vec![s("pin"), s("--out"), s(seal.to_str().unwrap())];
        for p in paths {
            args.push(s("--path"));
            args.push(s(p.to_str().unwrap()));
        }
        args
    }

    #[test]
    fn pin_verify_and_census() {
        assert_eq!(VERSION, "afterseal 0.1.0");
        assert_eq!(dispatch(&[s("version")]).unwrap(), 0);
        let names = toolchain_names();
        assert_eq!(names.len(), 6);
        for name in names {
            assert!(is_toolchain_basename(name), "{name}");
        }
        assert!(!is_toolchain_basename("xmrig"));

        let dir = tempfile::tempdir().unwrap();
        let paths = tools(dir.path());
        let seal = dir.path().join("seal.json");
        let seal_text = s(seal.to_str().unwrap());
        assert_eq!(dispatch(&pin_args(&seal, &paths)).unwrap(), 0);
        assert_eq!(
            dispatch(&[s("verify"), s("--seal"), seal_text.clone()]).unwrap(),
            0
        );
        assert_eq!(
            dispatch(&[s("census"), s("--seal"), seal_text.clone()]).unwrap(),
            0
        );
        std::fs::write(&paths[3], b"beta").unwrap();
        assert_eq!(
            dispatch(&[s("verify"), s("--seal"), seal_text.clone()]).unwrap(),
            3
        );
        let missing = dir.path().join("missing.json");
        assert_eq!(
            dispatch(&[s("verify"), s("--seal"), s(missing.to_str().unwrap())]).unwrap(),
            3
        );
        assert!(dispatch(&[s("pin"), s("--out"), seal_text.clone()]).is_err());
        let mut twice = pin_args(&seal, &paths);
        twice.splice(1..1, [s("--out"), s("other.json")]);
        assert!(dispatch(&twice).is_err());
        // One census binary short: pin refuses.
        assert!(dispatch(&pin_args(&seal, &paths[..5])).is_err());
        assert!(dispatch(&[s("census")]).is_err());
        assert_eq!(status_word(SealStatus::Valid), "valid");
        assert_eq!(status_word(SealStatus::Missing), "missing");
        assert_eq!(status_word(SealStatus::Mismatch), "mismatch");
    }

    #[test]
    fn census_inspects_files() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tools(dir.path());
        let seal = dir.path().join("seal.json");
        assert_eq!(dispatch(&pin_args(&seal, &paths)).unwrap(), 0);
        let (text, code) = census_report(&seal, false);
        assert_eq!(code, 0);
        assert!(text.contains("afterguard valid\n"));

        std::fs::write(&paths[3], b"replaced").unwrap();
        let (text, code) = census_report(&seal, false);
        assert_eq!(code, 3);
        assert!(text.contains("afterguard mismatch\n"));
        assert!(text.contains("nocved valid\n"));
        assert!(!text.contains("replaced"));

        let (json, code) = census_report(&seal, true);
        assert_eq!(code, 3);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["status"], "mismatch");
        assert_eq!(v["reason"], "seal_mismatch");
        assert_eq!(v["binaries"].as_array().unwrap().len(), 6);

        let (json, code) = census_report(&dir.path().join("none.json"), true);
        assert_eq!(code, 3);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["status"], "missing");
        assert_eq!(v["reason"], "seal_missing");
    }

    #[test]
    fn verify_json_has_status_and_reason() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tools(dir.path());
        let seal = dir.path().join("seal.json");
        assert_eq!(dispatch(&pin_args(&seal, &paths)).unwrap(), 0);
        let (json, code) = verify_report(&seal, true);
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["status"], "valid");
        assert_eq!(v["reason"], "sealed");
        std::fs::remove_file(&paths[0]).unwrap();
        let (json, code) = verify_report(&seal, true);
        assert_eq!(code, 3);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["status"], "mismatch");
        assert_eq!(v["reason"], "seal_mismatch");
        assert_eq!(
            dispatch(&[
                s("verify"),
                s("--json"),
                s("--seal"),
                s(seal.to_str().unwrap())
            ])
            .unwrap(),
            3
        );
    }
}

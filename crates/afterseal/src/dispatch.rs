//! `afterseal` commands. Pin refuses an empty path list and a list that
//! does not cover the six census binaries.
//!
//! Threats: a second `--out` would leave the operator unsure which manifest
//! was written. Verify and census print only status words (or the JSON
//! `status` / `reason` object darksignal reads), never file contents.

use std::path::{Path, PathBuf};

use cveguard_proto::cli::{self, CliError, Format};
use cveguard_proto::model::{MAX_SEAL_ENTRIES, basename};
use cveguard_proto::seal::{self, SealStatus};

use crate::toolchain_names;

pub const TOOL: &str = "afterseal";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const VERSION: &str = concat!("afterseal ", env!("CARGO_PKG_VERSION"));

const EXIT_CODES: &str = "Exit codes:
  0  success; verify/census: the seal is valid
  1  error (usage, I/O, refused pin); with --json one JSON error line on stderr
  3  verify/census: the seal is missing or mismatched (result still printed)";

const HELP: &str = "afterseal: toolchain SHA-256 pin and census for cveguard

Usage: afterseal <command> [--json | --format json|text]

Commands:
  version                               print the version
  pin --out PATH --path BIN [--path BIN ...]
                                        hash the six toolchain binaries into a 0600 manifest
  verify --seal PATH                    check every manifest entry
  census --seal PATH                    hash each of the six census binaries
  help [COMMAND]                        this text, or one command's help

Options (every command):
  --json, --format json   one JSON document on stdout (errors: one JSON line on stderr)
  --format text           human output (default)
  -h, --help              help for the command";

const HELP_VERSION: &str = "Usage: afterseal version [--json]

Prints the version. kind: afterseal.version";

const HELP_PIN: &str = "Usage: afterseal pin --out PATH --path BIN [--path BIN ...] [--json]

Hashes the given files (they must cover nocved, nocve-store, aftercve,
afterguard, afteralert, afterseal) into a 0600 manifest at --out and prints
the number of entries. kind: afterseal.pin";

const HELP_VERIFY: &str = "Usage: afterseal verify --seal PATH [--json]

Re-hashes every manifest entry. Prints valid, missing, or mismatch.
JSON adds status and reason (sealed, seal_missing, seal_mismatch).
kind: afterseal.verify";

const HELP_CENSUS: &str = "Usage: afterseal census --seal PATH [--json]

Hashes each census binary named in the manifest; one line per binary.
JSON: status, reason, binaries[{name,status}]. kind: afterseal.census";

pub fn dispatch(args: &[String]) -> Result<i32, CliError> {
    let inv = cli::split_output(args)?;
    let command = command_name(&inv.rest);
    run(&inv.rest, inv.format, inv.help).map_err(|e| e.with_command(command))
}

fn command_name(rest: &[String]) -> Option<&'static str> {
    match rest.first().map(String::as_str) {
        Some("version") => Some("version"),
        Some("pin") => Some("pin"),
        Some("verify") => Some("verify"),
        Some("census") => Some("census"),
        Some("help") => Some("help"),
        _ => None,
    }
}

fn run(rest: &[String], format: Format, help: bool) -> Result<i32, CliError> {
    if help {
        return print_help(rest.first().map(String::as_str));
    }
    match rest.first().map(String::as_str) {
        Some("help") if rest.len() <= 2 => print_help(rest.get(1).map(String::as_str)),
        Some("version" | "--version") if rest.len() == 1 => {
            match format {
                Format::Text => cli::print_line(VERSION)?,
                Format::Json => print(
                    "afterseal.version",
                    &serde_json::json!({"version": TOOL_VERSION}),
                )?,
            }
            Ok(0)
        }
        Some("census") => {
            let seal_path = seal_args(&rest[1..])?;
            let (text, code) = census_report(Path::new(seal_path), format == Format::Json)?;
            emit(&text)?;
            Ok(code)
        }
        Some("pin") => pin_cmd(&rest[1..], format),
        Some("verify") => {
            let seal_path = seal_args(&rest[1..])?;
            let (text, code) = verify_report(Path::new(seal_path), format == Format::Json)?;
            emit(&text)?;
            Ok(code)
        }
        Some(other) if !other.starts_with('-') && command_name(rest).is_none() => {
            Err(CliError::usage(format!(
                "unknown command {}; try afterseal --help",
                cli::clean(other)
            )))
        }
        None => Err(CliError::usage("missing command; try afterseal --help")),
        _ => Err(CliError::usage("bad arguments; try afterseal --help")),
    }
}

fn print_help(command: Option<&str>) -> Result<i32, CliError> {
    let body = match command {
        None | Some("help") => HELP,
        Some("version") => HELP_VERSION,
        Some("pin") => HELP_PIN,
        Some("verify") => HELP_VERIFY,
        Some("census") => HELP_CENSUS,
        Some(other) => {
            return Err(CliError::usage(format!(
                "no help for {}; try afterseal --help",
                cli::clean(other)
            )));
        }
    };
    cli::print_line(&format!("{body}\n\n{EXIT_CODES}"))?;
    Ok(0)
}

fn print(kind: &str, payload: &serde_json::Value) -> Result<(), CliError> {
    cli::print_envelope(TOOL, TOOL_VERSION, kind, payload)
}

/// Report text already ends in a newline.
fn emit(text: &str) -> Result<(), CliError> {
    cli::print_line(text.strip_suffix('\n').unwrap_or(text))
}

/// `--seal PATH`. The output flags were already removed.
fn seal_args(args: &[String]) -> Result<&str, CliError> {
    match args {
        [flag, path] if flag == "--seal" && !path.starts_with('-') => Ok(path),
        _ => Err(CliError::usage("expected --seal PATH")),
    }
}

fn pin_cmd(args: &[String], format: Format) -> Result<i32, CliError> {
    let mut out: Option<&str> = None;
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        let key = args[index].as_str();
        let Some(value) = args.get(index + 1) else {
            return Err(CliError::usage(format!(
                "{} needs a value",
                cli::clean(key)
            )));
        };
        if value.starts_with('-') {
            return Err(CliError::usage(format!(
                "{} value must not start with -",
                cli::clean(key)
            )));
        }
        match key {
            "--out" if out.is_none() => out = Some(value.as_str()),
            "--out" => return Err(CliError::usage("--out given twice")),
            "--path" => paths.push(PathBuf::from(value)),
            _ => {
                return Err(CliError::usage(format!("unknown flag {}", cli::clean(key))));
            }
        }
        index += 2;
    }
    let out = out.ok_or_else(|| CliError::usage("--out PATH is required"))?;
    if paths.is_empty() {
        return Err(CliError::usage("path required"));
    }
    if paths.len() > MAX_SEAL_ENTRIES {
        return Err(CliError::usage("too many seal entries"));
    }
    let manifest = seal::pin(&paths)?;
    seal::write_manifest(Path::new(out), &manifest)?;
    let entries = manifest.entries.len();
    match format {
        Format::Text => {
            cli::print_line(&format!("pinned {entries} entries to {}", cli::clean(out)))?
        }
        Format::Json => print(
            "afterseal.pin",
            &serde_json::json!({"out": out, "entries": entries, "status": "pinned"}),
        )?,
    }
    Ok(0)
}

fn reason(status: SealStatus) -> &'static str {
    match status {
        SealStatus::Valid => "sealed",
        SealStatus::Missing => "seal_missing",
        SealStatus::Mismatch => "seal_mismatch",
    }
}

fn verify_report(path: &Path, json: bool) -> Result<(String, i32), CliError> {
    let status = seal::verify(path);
    let text = if json {
        json_line(
            "afterseal.verify",
            &serde_json::json!({"status": status_word(status), "reason": reason(status)}),
        )?
    } else {
        format!("{}\n", status_word(status))
    };
    Ok((text, status_code(status)))
}

/// Inspects each census binary named in the manifest: hashes the file and
/// compares it with the pinned digest. A census name with no entry is
/// `missing`; a bad file is `mismatch`. Overall status is the worst one.
fn census_report(path: &Path, json: bool) -> Result<(String, i32), CliError> {
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
        json_line(
            "afterseal.census",
            &serde_json::json!({
                "status": status_word(overall),
                "reason": reason(overall),
                "binaries": binaries,
            }),
        )?
    } else {
        per.iter()
            .map(|(name, s)| format!("{name} {}\n", status_word(*s)))
            .collect()
    };
    Ok((text, status_code(overall)))
}

/// Envelope plus newline.
fn json_line(kind: &str, payload: &serde_json::Value) -> Result<String, CliError> {
    Ok(format!(
        "{}\n",
        cli::envelope(TOOL, TOOL_VERSION, kind, payload)?
    ))
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
        assert_eq!(VERSION, format!("afterseal {TOOL_VERSION}"));
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
        let (text, code) = census_report(&seal, false).unwrap();
        assert_eq!(code, 0);
        assert!(text.contains("afterguard valid\n"));

        std::fs::write(&paths[3], b"replaced").unwrap();
        let (text, code) = census_report(&seal, false).unwrap();
        assert_eq!(code, 3);
        assert!(text.contains("afterguard mismatch\n"));
        assert!(text.contains("nocved valid\n"));
        assert!(!text.contains("replaced"));

        let (json, code) = census_report(&seal, true).unwrap();
        assert_eq!(code, 3);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["status"], "mismatch");
        assert_eq!(v["reason"], "seal_mismatch");
        assert_eq!(v["binaries"].as_array().unwrap().len(), 6);

        let (json, code) = census_report(&dir.path().join("none.json"), true).unwrap();
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
        let (json, code) = verify_report(&seal, true).unwrap();
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["status"], "valid");
        assert_eq!(v["reason"], "sealed");
        std::fs::remove_file(&paths[0]).unwrap();
        let (json, code) = verify_report(&seal, true).unwrap();
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

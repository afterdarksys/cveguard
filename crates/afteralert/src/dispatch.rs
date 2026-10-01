//! `afteralert` commands. Tests drive `serve_listener` on an ephemeral
//! loopback port with a connection limit, never the unbounded `serve`.
//!
//! Threats: a duplicated flag or a value that looks like a flag is rejected
//! so the listen address cannot be swapped by a typo.

use std::net::SocketAddr;
use std::path::Path;

use cveguard_proto::cli::{self, Category, CliError, Format};

use crate::serve::{self, parse_listen};

pub const TOOL: &str = "afteralert";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const VERSION: &str = concat!("afteralert ", env!("CARGO_PKG_VERSION"));

const EXIT_CODES: &str = "Exit codes:
  0  success
  1  error (usage, bad --listen, unreadable ledger or gauges); with --json one
     JSON error line on stderr";

const HELP: &str = "afteralert: Prometheus text for cveguard decisions on 127.0.0.1

Usage: afteralert <command> [--json | --format json|text]

Commands:
  version                               print the version
  serve --listen 127.0.0.1:PORT --ledger PATH [--gauges PATH]
                                        serve /metrics (daemon; /metrics is its status)
  help [COMMAND]                        this text, or one command's help

Options (every command):
  --json, --format json   JSON on stdout; errors as one JSON line on stderr
  --format text           human output (default)
  -h, --help              help for the command";

const HELP_VERSION: &str = "Usage: afteralert version [--json]

Prints the version. kind: afteralert.version";

const HELP_SERVE: &str =
    "Usage: afteralert serve --listen 127.0.0.1:PORT --ledger PATH [--gauges PATH] [--json]

Daemon. Serves GET /metrics on loopback only; nothing is printed on stdout.
--gauges is the status.json afterguard run writes. The scrape is this
daemon's status: there is no separate status file. With --json, a startup
or fatal error is one JSON line on stderr.";

pub fn dispatch(args: &[String]) -> Result<i32, CliError> {
    let inv = cli::split_output(args)?;
    let command = match inv.rest.first().map(String::as_str) {
        Some("version") => Some("version"),
        Some("serve") => Some("serve"),
        Some("help") => Some("help"),
        _ => None,
    };
    run(&inv.rest, inv.format, inv.help).map_err(|e| e.with_command(command))
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
                Format::Json => cli::print_envelope(
                    TOOL,
                    TOOL_VERSION,
                    "afteralert.version",
                    &serde_json::json!({"version": TOOL_VERSION}),
                )?,
            }
            Ok(0)
        }
        Some("serve") => serve_cmd(&rest[1..]),
        Some(other) if !matches!(other, "version" | "help") && !other.starts_with('-') => {
            Err(CliError::usage(format!(
                "unknown command {}; try afteralert --help",
                cli::clean(other)
            )))
        }
        None => Err(CliError::usage("missing command; try afteralert --help")),
        _ => Err(CliError::usage("bad arguments; try afteralert --help")),
    }
}

fn print_help(command: Option<&str>) -> Result<i32, CliError> {
    let body = match command {
        None | Some("help") => HELP,
        Some("version") => HELP_VERSION,
        Some("serve") => HELP_SERVE,
        Some(other) => {
            return Err(CliError::usage(format!(
                "no help for {}; try afteralert --help",
                cli::clean(other)
            )));
        }
    };
    cli::print_line(&format!("{body}\n\n{EXIT_CODES}"))?;
    Ok(0)
}

fn serve_cmd(args: &[String]) -> Result<i32, CliError> {
    let mut listen: Option<&str> = None;
    let mut ledger: Option<&str> = None;
    let mut gauges: Option<&str> = None;
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
            "--listen" if listen.is_none() => listen = Some(value.as_str()),
            "--ledger" if ledger.is_none() => ledger = Some(value.as_str()),
            "--gauges" if gauges.is_none() => gauges = Some(value.as_str()),
            "--listen" | "--ledger" | "--gauges" => {
                return Err(CliError::usage(format!("{key} given twice")));
            }
            _ => return Err(CliError::usage(format!("unknown flag {}", cli::clean(key)))),
        }
        index += 2;
    }
    let listen = listen.ok_or_else(|| CliError::usage("--listen 127.0.0.1:PORT is required"))?;
    let ledger = ledger.ok_or_else(|| CliError::usage("--ledger PATH is required"))?;
    let addr: SocketAddr = parse_listen(listen)
        .map_err(|_| CliError::new(Category::Config, "--listen must be 127.0.0.1:PORT", 1))?;
    Ok(serve::serve(
        addr,
        Path::new(ledger),
        gauges.map(Path::new),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_flags() {
        assert_eq!(VERSION, format!("afteralert {TOOL_VERSION}"));
        assert_eq!(dispatch(&["version".to_owned()]).unwrap(), 0);
        assert!(dispatch(&["version".to_owned(), "extra".to_owned()]).is_err());
        assert!(
            dispatch(&[
                "serve".to_owned(),
                "--listen".to_owned(),
                "0.0.0.0:8752".to_owned(),
                "--ledger".to_owned(),
                "decisions.jsonl".to_owned(),
            ])
            .is_err()
        );
        assert!(
            dispatch(&[
                "serve".to_owned(),
                "--listen".to_owned(),
                "-1".to_owned(),
                "--ledger".to_owned(),
                "decisions.jsonl".to_owned(),
            ])
            .is_err()
        );
        assert!(
            dispatch(&[
                "serve".to_owned(),
                "--listen".to_owned(),
                "127.0.0.1:8752".to_owned(),
                "--listen".to_owned(),
                "127.0.0.1:8753".to_owned(),
                "--ledger".to_owned(),
                "decisions.jsonl".to_owned(),
            ])
            .is_err()
        );
        assert!(
            dispatch(&[
                "serve".to_owned(),
                "--listen".to_owned(),
                "127.0.0.1:8752".to_owned()
            ])
            .is_err()
        );
    }
}

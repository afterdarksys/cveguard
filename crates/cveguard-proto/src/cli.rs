//! After Dark CLI output contract (`docs/output-contract.md`): output flag
//! parsing, the JSON success envelope, and the JSON error line.
//!
//! Threats: an error message must not carry raw untrusted bytes into a
//! terminal or a log pipeline, so control and bidi characters are escaped
//! before any message is printed, in either mode. Unknown output formats are
//! a usage error, never a silent fallback to text. Not covered: what a
//! caller puts in a payload; callers keep secrets and file contents out.

use std::fmt;
use std::io::Write;

use serde_json::Value;

use crate::error::Error;

/// `schema_version` of every envelope this workspace prints or writes.
pub const OUTPUT_SCHEMA_VERSION: u64 = 1;

const ENVELOPE_KEYS: [&str; 4] = ["schema_version", "kind", "tool", "tool_version"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Usage,
    Config,
    Io,
    Refused,
    Integrity,
    Verification,
    Transport,
    Budget,
    Internal,
}

impl Category {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::Config => "config",
            Self::Io => "io",
            Self::Refused => "refused",
            Self::Integrity => "integrity",
            Self::Verification => "verification",
            Self::Transport => "transport",
            Self::Budget => "budget",
            Self::Internal => "internal",
        }
    }
}

/// A command failure. `exit_code` is what the process exits with.
#[derive(Debug)]
pub struct CliError {
    pub category: Category,
    pub message: String,
    pub exit_code: i32,
    pub command: Option<String>,
}

impl CliError {
    #[must_use]
    pub fn new(category: Category, message: impl Into<String>, exit_code: i32) -> Self {
        Self {
            category,
            message: message.into(),
            exit_code,
            command: None,
        }
    }

    /// Usage error. This workspace keeps exit 1 for it (see README).
    #[must_use]
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Category::Usage, message, 1)
    }

    /// A config file that cannot be loaded, whatever the underlying error.
    #[must_use]
    pub fn config(err: &Error) -> Self {
        Self::new(Category::Config, format!("config: {err}"), 1)
    }

    #[must_use]
    pub fn with_command(mut self, command: Option<&str>) -> Self {
        if self.command.is_none() {
            self.command = command.map(str::to_owned);
        }
        self
    }
}

impl From<Error> for CliError {
    fn from(err: Error) -> Self {
        let category = match &err {
            Error::Io(_) => Category::Io,
            Error::Schema(_) => Category::Integrity,
            Error::Invalid(_) => Category::Config,
            Error::NotInDebut(_) => Category::Refused,
            Error::Busy | Error::Full => Category::Internal,
        };
        Self::new(category, err.to_string(), 1)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// Arguments with the output flags removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub format: Format,
    pub help: bool,
    pub rest: Vec<String>,
}

/// Removes `--json`, `--format json|text`, `-h`, and `--help` from `args`.
/// A repeated or conflicting output flag, or another format, is a usage error.
pub fn split_output(args: &[String]) -> Result<Invocation, CliError> {
    let mut json = false;
    let mut format: Option<Format> = None;
    let mut help = false;
    let mut rest = Vec::with_capacity(args.len());
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                if json {
                    return Err(CliError::usage("--json given twice"));
                }
                json = true;
            }
            "--format" => {
                let value = match args.get(index + 1).map(String::as_str) {
                    Some("json") => Format::Json,
                    Some("text") => Format::Text,
                    _ => return Err(CliError::usage("--format takes json or text")),
                };
                if format.is_some() {
                    return Err(CliError::usage("--format given twice"));
                }
                format = Some(value);
                index += 1;
            }
            "-h" | "--help" => help = true,
            _ => rest.push(args[index].clone()),
        }
        index += 1;
    }
    if json && format == Some(Format::Text) {
        return Err(CliError::usage("--json conflicts with --format text"));
    }
    let format = if json || format == Some(Format::Json) {
        Format::Json
    } else {
        Format::Text
    };
    Ok(Invocation { format, help, rest })
}

/// Best-effort format for reporting an error when `split_output` itself
/// failed: JSON when `--json` or `--format json` appears anywhere.
#[must_use]
pub fn sniff_format(args: &[String]) -> Format {
    let json = args.iter().any(|a| a == "--json")
        || args
            .windows(2)
            .any(|pair| pair[0] == "--format" && pair[1] == "json");
    if json { Format::Json } else { Format::Text }
}

/// One compact JSON object: the four envelope fields first, then the
/// payload's fields. Payload keys that collide with the envelope are dropped.
pub fn envelope(
    tool: &str,
    version: &str,
    kind: &str,
    payload: &Value,
) -> Result<String, CliError> {
    let Value::Object(map) = payload else {
        return Err(CliError::new(
            Category::Internal,
            "payload is not an object",
            1,
        ));
    };
    let mut out = format!(
        "{{\"schema_version\":{OUTPUT_SCHEMA_VERSION},\"kind\":{},\"tool\":{},\"tool_version\":{}",
        json_text(&Value::from(kind))?,
        json_text(&Value::from(tool))?,
        json_text(&Value::from(version))?,
    );
    for (key, value) in map {
        if ENVELOPE_KEYS.contains(&key.as_str()) {
            continue;
        }
        out.push(',');
        out.push_str(&json_text(&Value::from(key.as_str()))?);
        out.push(':');
        out.push_str(&json_text(value)?);
    }
    out.push('}');
    Ok(out)
}

fn json_text(value: &Value) -> Result<String, CliError> {
    serde_json::to_string(value).map_err(|_| CliError::new(Category::Internal, "json rejected", 1))
}

/// The section 3 error object, one line, no trailing newline.
#[must_use]
pub fn error_line(tool: &str, err: &CliError) -> String {
    // Built by hand so the field order matches the contract. `Value`'s
    // Display is compact JSON with string escaping.
    let command = err.command.as_deref().map_or(Value::Null, Value::from);
    format!(
        "{{\"schema_version\":{OUTPUT_SCHEMA_VERSION},\"kind\":\"error\",\"tool\":{},\"command\":{},\"category\":{},\"message\":{},\"exit_code\":{}}}",
        Value::from(tool),
        command,
        Value::from(err.category.as_str()),
        Value::from(clean(&err.message)),
        err.exit_code,
    )
}

/// Escapes control characters and Unicode bidi overrides as `\u{..}`.
#[must_use]
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let bidi = matches!(
            ch,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        );
        if ch.is_control() || bidi {
            out.push_str(&format!("\\u{{{:04x}}}", u32::from(ch)));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Writes one line to stdout. A closed stdout is an I/O error, not a panic.
pub fn print_line(line: &str) -> Result<(), CliError> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}")
        .and_then(|()| out.flush())
        .map_err(|e| CliError::new(Category::Io, format!("stdout: {e}"), 1))
}

/// Prints `payload` as an envelope on stdout.
pub fn print_envelope(
    tool: &str,
    version: &str,
    kind: &str,
    payload: &Value,
) -> Result<(), CliError> {
    print_line(&envelope(tool, version, kind, payload)?)
}

/// Prints a failure on stderr (JSON line or `<tool>: <message>`) and
/// returns its exit code. `Ok(code)` passes through.
#[must_use]
pub fn finish(tool: &str, args: &[String], result: Result<i32, CliError>) -> i32 {
    match result {
        Ok(code) => code,
        Err(err) => {
            let line = match sniff_format(args) {
                Format::Json => error_line(tool, &err),
                Format::Text => format!("{tool}: {}", clean(&err.message)),
            };
            eprintln!("{line}");
            err.exit_code
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn envelope_fields_come_first_and_cannot_be_overridden() {
        let line = envelope(
            "afterseal",
            "0.1.0",
            "afterseal.verify",
            &serde_json::json!({"status": "valid", "kind": "x", "tool": "y"}),
        )
        .unwrap();
        assert!(line.starts_with(
            "{\"schema_version\":1,\"kind\":\"afterseal.verify\",\"tool\":\"afterseal\",\"tool_version\":\"0.1.0\","
        ));
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["kind"], "afterseal.verify");
        assert_eq!(v["tool"], "afterseal");
        assert_eq!(v["status"], "valid");
        assert!(!line.contains('\n'));
        assert!(envelope("t", "1", "t.x", &Value::Null).is_err());
    }

    #[test]
    fn error_line_has_the_six_fields_in_order_and_escapes() {
        let err = CliError::usage("bad \u{202E}flag\n").with_command(Some("check"));
        let line = error_line("afterguard", &err);
        assert!(line.starts_with(
            "{\"schema_version\":1,\"kind\":\"error\",\"tool\":\"afterguard\",\"command\":\"check\",\"category\":\"usage\","
        ));
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["exit_code"], 1);
        let message = v["message"].as_str().unwrap();
        assert!(!message.contains('\u{202E}'));
        assert!(!message.contains('\n'));
        assert!(message.contains("\\u{202e}"));
        let none = error_line("afterguard", &CliError::usage("x"));
        let v: Value = serde_json::from_str(&none).unwrap();
        assert!(v["command"].is_null());
    }

    #[test]
    fn split_output_strips_flags_and_rejects_conflicts() {
        let inv = split_output(&s(&["check", "--json", "--config", "a"])).unwrap();
        assert_eq!(inv.format, Format::Json);
        assert_eq!(inv.rest, s(&["check", "--config", "a"]));
        let inv = split_output(&s(&["check", "--format", "json"])).unwrap();
        assert_eq!(inv.format, Format::Json);
        let inv = split_output(&s(&["check", "--format", "text", "-h"])).unwrap();
        assert_eq!(inv.format, Format::Text);
        assert!(inv.help);
        for bad in [
            &["--json", "--json"][..],
            &["--format", "html"],
            &["--format"],
            &["--format", "json", "--format", "json"],
            &["--json", "--format", "text"],
        ] {
            let err = split_output(&s(bad)).unwrap_err();
            assert_eq!(err.category, Category::Usage, "{bad:?}");
        }
        assert_eq!(sniff_format(&s(&["x", "--format", "json"])), Format::Json);
        assert_eq!(sniff_format(&s(&["x", "--json"])), Format::Json);
        assert_eq!(sniff_format(&s(&["x"])), Format::Text);
    }

    #[test]
    fn proto_errors_map_to_categories() {
        let io: CliError = Error::Io(std::io::Error::other("x")).into();
        assert_eq!(io.category, Category::Io);
        let refused: CliError = Error::NotInDebut("no").into();
        assert_eq!(refused.category, Category::Refused);
        assert_eq!(refused.exit_code, 1);
        assert_eq!(
            CliError::config(&Error::Invalid("x".into())).category,
            Category::Config
        );
    }
}

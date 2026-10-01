//! `afteralert` commands. Tests drive `serve_listener` on an ephemeral
//! loopback port with a connection limit, never the unbounded `serve`.
//!
//! Threats: a duplicated flag or a value that looks like a flag is rejected
//! so the listen address cannot be swapped by a typo.

use std::net::SocketAddr;
use std::path::Path;

use cveguard_proto::Error;

use crate::serve::{self, parse_listen};

pub const VERSION: &str = "afteralert 0.1.0";

pub fn dispatch(args: &[String]) -> Result<i32, Error> {
    match args.first().map(String::as_str) {
        Some("version") if args.len() == 1 => {
            println!("{VERSION}");
            Ok(0)
        }
        Some("serve") => serve_cmd(&args[1..]),
        _ => Err(usage()),
    }
}

fn serve_cmd(args: &[String]) -> Result<i32, Error> {
    let mut listen: Option<&str> = None;
    let mut ledger: Option<&str> = None;
    let mut gauges: Option<&str> = None;
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
            "--listen" if listen.is_none() => listen = Some(value.as_str()),
            "--ledger" if ledger.is_none() => ledger = Some(value.as_str()),
            "--gauges" if gauges.is_none() => gauges = Some(value.as_str()),
            _ => return Err(usage()),
        }
        index += 2;
    }
    let listen = listen.ok_or_else(usage)?;
    let ledger = ledger.ok_or_else(usage)?;
    let addr: SocketAddr = parse_listen(listen)?;
    serve::serve(addr, Path::new(ledger), gauges.map(Path::new))
}

fn usage() -> Error {
    Error::Invalid("usage".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_flags() {
        assert_eq!(VERSION, "afteralert 0.1.0");
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

//! Loopback HTTP for `/metrics`. The request is not copied into the response.
//!
//! Threats: binding a public address would publish decisions off the host.
//! A huge header is rejected before it is parsed. Broken clients do not stop
//! the accept loop; a ledger that cannot be read fails the process closed.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;

use cveguard_proto::Error;

use crate::snapshot::{self, Snapshot};

const HEADER_LIMIT: usize = 2048;

enum HeaderRead {
    Ready(String),
    Reject,
}

pub fn parse_listen(text: &str) -> Result<SocketAddr, Error> {
    let Some((host, port)) = text.rsplit_once(':') else {
        return Err(Error::Invalid("listen rejected".to_owned()));
    };
    if host != "127.0.0.1" {
        return Err(Error::Invalid("listen rejected".to_owned()));
    }
    if port.is_empty()
        || (port.len() > 1 && port.starts_with('0'))
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::Invalid("listen rejected".to_owned()));
    }
    let value: u16 = port
        .parse()
        .map_err(|_| Error::Invalid("listen rejected".to_owned()))?;
    if value == 0 {
        return Err(Error::Invalid("listen rejected".to_owned()));
    }
    Ok(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), value)))
}

pub fn serve(addr: SocketAddr, ledger: &Path, gauges: Option<&Path>) -> Result<i32, Error> {
    let listener = TcpListener::bind(addr)?;
    loop {
        let (mut stream, _) = listener.accept()?;
        let snapshot = snapshot::load_snapshot(ledger, gauges)?;
        if let Err(err) = serve_one(&mut stream, &snapshot)
            && err.kind() != io::ErrorKind::BrokenPipe
            && err.kind() != io::ErrorKind::ConnectionReset
        {
            return Err(err.into());
        }
    }
}

pub fn serve_one(stream: &mut TcpStream, snapshot: &Snapshot) -> io::Result<()> {
    let header = match read_header(stream)? {
        HeaderRead::Reject => return respond(stream, 400, "bad request", "bad request\n"),
        HeaderRead::Ready(text) => text,
    };
    match classify(&header) {
        200 => respond(stream, 200, "OK", &snapshot::render(snapshot)),
        404 => respond(stream, 404, "not found", "not found\n"),
        _ => respond(stream, 400, "bad request", "bad request\n"),
    }
}

fn classify(header: &str) -> u16 {
    let Some(line) = header.lines().next() else {
        return 400;
    };
    let mut parts = line.split(' ');
    let Some(method) = parts.next() else {
        return 400;
    };
    if method != "GET" {
        return 400;
    }
    let Some(path) = parts.next() else {
        return 400;
    };
    if path != "/metrics" {
        return 404;
    }
    match parts.next() {
        Some(version) if version.starts_with("HTTP/1.") && parts.next().is_none() => 200,
        _ => 400,
    }
}

fn read_header(stream: &mut TcpStream) -> io::Result<HeaderRead> {
    let mut buf = [0u8; HEADER_LIMIT + 1];
    let mut filled = 0usize;
    loop {
        if let Some(end) = header_end(&buf[..filled]) {
            return finish_header(end, &buf[..end]);
        }
        if filled == buf.len() {
            return Ok(HeaderRead::Reject);
        }
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Ok(HeaderRead::Reject),
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

fn finish_header(end: usize, bytes: &[u8]) -> io::Result<HeaderRead> {
    if end > HEADER_LIMIT {
        return Ok(HeaderRead::Reject);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => Ok(HeaderRead::Ready(text.to_owned())),
        Err(_) => Ok(HeaderRead::Reject),
    }
}

fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn respond(stream: &mut TcpStream, status: u16, reason: &str, body: &str) -> io::Result<()> {
    let ctype = if status == 200 {
        "text/plain; version=0.0.4; charset=utf-8"
    } else {
        "text/plain; charset=utf-8"
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        len = body.len(),
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::Shutdown;

    fn exchange(request: &[u8]) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let snapshot =
            snapshot::load_snapshot(Path::new("/no/such/cveguard-ledger"), None).unwrap();
        serve_one(&mut server, &snapshot).unwrap();
        drop(server);
        let mut body = Vec::new();
        client.read_to_end(&mut body).unwrap();
        body
    }

    fn header_of_len(total: usize) -> Vec<u8> {
        let prefix = b"GET /metrics HTTP/1.1\r\nX: ";
        let suffix = b"\r\n\r\n";
        let pad = total - prefix.len() - suffix.len();
        let mut bytes = prefix.to_vec();
        bytes.extend(std::iter::repeat_n(b'b', pad));
        bytes.extend_from_slice(suffix);
        bytes
    }

    #[test]
    fn parse_listen_is_loopback_only() {
        assert_eq!(
            parse_listen("127.0.0.1:8752").unwrap(),
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 8752))
        );
        for sample in [
            "0.0.0.0:8752",
            "127.0.0.1:0",
            "127.0.0.1:08752",
            "localhost:8752",
            "::1:8752",
            "127.0.0.1",
        ] {
            assert!(parse_listen(sample).is_err(), "{sample}");
        }
    }

    #[test]
    fn rejects_non_get_unknown_path_oversize_and_bad_utf8() {
        let ok = exchange(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let ok_text = std::str::from_utf8(&ok).unwrap();
        assert!(ok_text.starts_with("HTTP/1.1 200 "));
        assert!(
            ok_text.contains("cveguard_decisions_total{action=\"record\",outcome=\"shadow\"} 0\n")
        );

        let post = exchange(b"POST /nope HTTP/1.1\r\n\r\n");
        let post_text = std::str::from_utf8(&post).unwrap();
        assert!(post_text.starts_with("HTTP/1.1 400 "));
        assert!(!post_text.contains("404"));

        let missing = exchange(b"GET /nope HTTP/1.1\r\n\r\n");
        assert!(
            std::str::from_utf8(&missing)
                .unwrap()
                .starts_with("HTTP/1.1 404 ")
        );

        let huge = exchange(&header_of_len(2049));
        let huge_text = std::str::from_utf8(&huge).unwrap();
        assert!(huge_text.starts_with("HTTP/1.1 400 "));
        assert!(!huge_text.contains("bbbbb"));

        let fitted = exchange(&header_of_len(2048));
        assert!(
            std::str::from_utf8(&fitted)
                .unwrap()
                .starts_with("HTTP/1.1 200 ")
        );

        let bad = exchange(b"GET /metrics HTTP/1.1\r\nX: \xff\r\n\r\n");
        assert!(bad.starts_with(b"HTTP/1.1 400 "));
        assert!(!bad.contains(&0xff));
    }
}

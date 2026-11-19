//! `<server> healthcheck`: a liveness probe the distroless image can run itself.
//!
//! The runtime image has no shell, curl or wget, so Docker's `HEALTHCHECK`
//! (and Swarm) invoke the binary: one plain HTTP GET on the local `/health`,
//! exit 0 on `200`, 1 otherwise. No TLS: the probe always targets the plain
//! listener inside the container.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

/// `GET http://<addr>/health`; `Ok` only for an HTTP 200.
pub fn check(addr: SocketAddr, timeout: Duration) -> Result<(), String> {
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| e.to_string())?;
    write!(
        stream,
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| format!("write: {e}"))?;

    let mut head = [0u8; 32];
    let n = stream.read(&mut head).map_err(|e| format!("read: {e}"))?;
    let status_line = String::from_utf8_lossy(&head[..n]);
    match status_line.split_whitespace().nth(1) {
        Some("200") => Ok(()),
        Some(code) => Err(format!("/health answered {code}")),
        None => Err("no HTTP status line".to_string()),
    }
}

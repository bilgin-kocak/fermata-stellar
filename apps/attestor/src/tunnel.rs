//! The vendor socket through an HTTP `CONNECT` proxy (for provers behind an egress proxy).
//!
//! Only the vendor connection is tunnelled, never the notary's. The proxy relays the TLS bytes
//! untouched: MPC-TLS runs end to end with the vendor, and the vendor's certificate is checked
//! against the trust roots by the prover, the notary and every verifier. A proxy that terminates
//! TLS itself (an intercepting proxy) therefore presents a certificate that does not chain to the
//! roots, and the session fails, as it must.
//!
//! Copied unchanged from Fermata `apps/attestor/src/tunnel.rs` @ d7cc642
//! (github.com/bilgin-kocak/fermata, Apache-2.0).

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// A parsed `http://[user:pass@]host:port[/]` proxy URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proxy {
    pub addr: String,
    pub auth: Option<String>,
}

impl Proxy {
    pub fn parse(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| anyhow!("upstream proxy must be an http:// URL, got {url}"))?;
        let rest = rest.trim_end_matches('/');
        ensure!(
            !rest.contains('/'),
            "upstream proxy URL must not have a path: {url}"
        );
        let (auth, addr) = match rest.rsplit_once('@') {
            Some((auth, addr)) => (Some(auth.to_string()), addr),
            None => (None, rest),
        };
        ensure!(addr.contains(':'), "upstream proxy needs host:port: {url}");
        Ok(Self {
            addr: addr.to_string(),
            auth,
        })
    }
}

/// Opens a TCP tunnel to `authority` (`host:port`) through `proxy`.
pub async fn connect(proxy: &Proxy, authority: &str) -> Result<TcpStream> {
    let mut socket = TcpStream::connect(&proxy.addr)
        .await
        .with_context(|| format!("connecting to upstream proxy {}", proxy.addr))?;
    socket.set_nodelay(true)?;
    let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = &proxy.auth {
        let token = base64::engine::general_purpose::STANDARD.encode(auth);
        head.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    head.push_str("\r\n");
    socket.write_all(head.as_bytes()).await?;

    // Read the response head byte by byte: nothing after it may be consumed, it belongs to TLS.
    let mut buf = Vec::with_capacity(256);
    while !buf.ends_with(b"\r\n\r\n") {
        ensure!(buf.len() < 8192, "upstream proxy response head too long");
        let mut byte = [0u8; 1];
        if socket.read(&mut byte).await? == 0 {
            bail!("upstream proxy closed the connection during CONNECT {authority}");
        }
        buf.push(byte[0]);
    }
    let status_line =
        String::from_utf8_lossy(&buf[..buf.iter().position(|b| *b == b'\r').unwrap_or(0)])
            .to_string();
    let code = status_line.split_whitespace().nth(1).unwrap_or("");
    ensure!(
        status_line.starts_with("HTTP/1.") && code == "200",
        "upstream proxy refused CONNECT {authority}: {status_line}"
    );
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A one-shot proxy: records the request head, answers `reply`, then echoes.
    async fn mock_proxy(reply: &'static [u8]) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut b = [0u8; 1];
                if s.read(&mut b).await.unwrap() == 0 {
                    break;
                }
                head.push(b[0]);
            }
            s.write_all(reply).await.unwrap();
            let mut echo = [0u8; 5];
            if s.read_exact(&mut echo).await.is_ok() {
                s.write_all(&echo).await.unwrap();
            }
            String::from_utf8(head).unwrap()
        });
        (addr, task)
    }

    #[test]
    fn parses_proxy_urls() {
        assert_eq!(
            Proxy::parse("http://127.0.0.1:3128").unwrap(),
            Proxy {
                addr: "127.0.0.1:3128".into(),
                auth: None
            }
        );
        assert_eq!(
            Proxy::parse("http://user:p@ss@proxy.local:8080/").unwrap(),
            Proxy {
                addr: "proxy.local:8080".into(),
                auth: Some("user:p@ss".into())
            }
        );
        assert!(Proxy::parse("https://proxy:443").is_err());
        assert!(Proxy::parse("http://proxy").is_err());
        assert!(Proxy::parse("http://proxy:1/path").is_err());
    }

    #[tokio::test]
    async fn tunnels_after_200_and_leaves_the_stream_untouched() {
        let (addr, task) = mock_proxy(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
        let proxy = Proxy {
            addr,
            auth: Some("u:pw".into()),
        };
        let mut s = connect(&proxy, "registry.npmjs.org:443").await.unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");
        let head = task.await.unwrap();
        assert!(head.starts_with(
            "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n"
        ));
        assert!(head.contains("Proxy-Authorization: Basic dTpwdw==\r\n"));
    }

    #[tokio::test]
    async fn refuses_a_non_200_answer() {
        let (addr, _task) =
            mock_proxy(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
        let err = connect(&Proxy { addr, auth: None }, "api.example.com:443")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("403"), "{err}");
    }

    #[tokio::test]
    async fn refuses_garbage_and_hang_ups() {
        let (addr, _task) = mock_proxy(b"SSH-2.0-OpenSSH\r\n\r\n").await;
        assert!(
            connect(&Proxy { addr, auth: None }, "a.example:443")
                .await
                .is_err()
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { drop(listener.accept().await) });
        assert!(
            connect(&Proxy { addr, auth: None }, "a.example:443")
                .await
                .is_err()
        );
    }
}

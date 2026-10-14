//! Minimal HTTP/1.1 parsing over the *raw* revealed transcript bytes.
//! Deliberately independent of tlsn-formats so that a malformed body (truncated JSON,
//! wrong Content-Length) still yields a status line and headers for the predicate.
//!
//! Copied from Fermata `apps/attestor/src/http_raw.rs` @ d7cc642
//! (github.com/bilgin-kocak/fermata, Apache-2.0); unchanged apart from one line `cargo fmt` wraps.

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone)]
pub struct RawRequest {
    pub method: String,
    pub target: String,
    /// header names lower-cased
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Body bytes as received (may be shorter than Content-Length if the server cut it off).
    pub body: Vec<u8>,
}

pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let n = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| *k == n)
        .map(|(_, v)| v.as_str())
}

pub fn parse_request(bytes: &[u8]) -> Result<RawRequest> {
    let mut hdrs = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut hdrs);
    let status = req.parse(bytes).context("request head does not parse")?;
    let head_len = match status {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => bail!("request head incomplete"),
    };
    let headers = req
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                String::from_utf8_lossy(h.value).to_string(),
            )
        })
        .collect::<Vec<_>>();
    Ok(RawRequest {
        method: req.method.context("no method")?.to_string(),
        target: req.path.context("no target")?.to_string(),
        headers,
        body: bytes[head_len..].to_vec(),
    })
}

pub fn parse_response(bytes: &[u8]) -> Result<RawResponse> {
    let mut hdrs = [httparse::EMPTY_HEADER; 64];
    let mut res = httparse::Response::new(&mut hdrs);
    let status = res.parse(bytes).context("response head does not parse")?;
    let head_len = match status {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => bail!("response head incomplete"),
    };
    let headers = res
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                String::from_utf8_lossy(h.value).to_string(),
            )
        })
        .collect::<Vec<_>>();
    let raw_body = &bytes[head_len..];
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    Ok(RawResponse {
        status: res.code.context("no status code")?,
        headers,
        body: if chunked {
            decode_chunked(raw_body)
        } else {
            raw_body.to_vec()
        },
    })
}

/// Decodes a `Transfer-Encoding: chunked` body (chunk extensions and trailers ignored). A body cut
/// short (the server closed mid-chunk) decodes to the bytes that arrived; the predicate judges them.
pub fn decode_chunked(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = b.windows(2).position(|w| w == b"\r\n") {
        let line = std::str::from_utf8(&b[..eol]).unwrap_or("");
        let Ok(size) = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
        else {
            break;
        };
        b = &b[eol + 2..];
        if size == 0 {
            break;
        }
        let take = size.min(b.len());
        out.extend_from_slice(&b[..take]);
        b = &b[take..];
        if take < size || !b.starts_with(b"\r\n") {
            break;
        }
        b = &b[2..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_bodies_are_decoded() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n7;ext=1\r\n{\"a\":1,\r\n6\r\n\"b\":2}\r\n0\r\nX-Trailer: t\r\n\r\n";
        let res = parse_response(raw).unwrap();
        assert_eq!(res.status, 200);
        assert_eq!(res.body, b"{\"a\":1,\"b\":2}");
    }

    #[test]
    fn plain_and_truncated_bodies() {
        let plain = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!(plain.body, b"{}");
        // cut mid-chunk: what arrived, no framing
        assert_eq!(decode_chunked(b"a\r\n0123"), b"0123");
        assert_eq!(decode_chunked(b"not hex\r\n"), b"");
    }
}

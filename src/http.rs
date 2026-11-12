//! Serving HTTPS with limits: a cap on simultaneous connections (overall and
//! per address), deadlines for the TLS handshake and request headers, and a
//! maximum connection lifetime, so slow or idle clients can't tie the
//! service up. Plus the security headers and request deadline every response
//! gets. A plain-HTTP request is never served: it gets a redirect to the
//! https:// address and the connection is closed.

use axum::extract::{ConnectInfo, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tower::ServiceExt;

/// Connection limits for one listener.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Simultaneous connections in total.
    pub max_connections: usize,
    /// Simultaneous connections from one address (not applied to trusted
    /// proxies such as cloudflared, which carry everyone's traffic).
    pub per_address: usize,
    /// Time allowed to send a request's headers.
    pub header_timeout: Duration,
    /// A connection is closed after this long however busy it is (browsers
    /// simply open a new one).
    pub max_lifetime: Duration,
}

impl Limits {
    pub fn web() -> Limits {
        Limits { max_connections: 256, per_address: 64, header_timeout: Duration::from_secs(15), max_lifetime: Duration::from_secs(600) }
    }

    pub fn share() -> Limits {
        Limits { max_connections: 512, per_address: 16, header_timeout: Duration::from_secs(10), max_lifetime: Duration::from_secs(600) }
    }
}

/// Counts connections per address; decrements when dropped.
struct AddrSlot {
    map: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for AddrSlot {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap();
        if let Some(n) = m.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

/// Serve `app` over HTTPS on `listener` until `stop` turns true. `exempt`
/// says whether an address is a trusted proxy (no per-address cap).
pub async fn serve(
    listener: TcpListener,
    app: Router,
    limits: Limits,
    exempt: Arc<dyn Fn(IpAddr) -> bool + Send + Sync>,
    tls: Arc<rustls::ServerConfig>,
    stop: watch::Receiver<bool>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let stopped = async move {
        let mut rx = stop;
        let _ = rx.wait_for(|v| *v).await;
    };
    tokio::pin!(stopped);
    let total = Arc::new(Semaphore::new(limits.max_connections));
    let per_addr: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    // Usually out of file descriptors: back off briefly.
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = &mut stopped => break,
        };
        let Ok(permit) = total.clone().try_acquire_owned() else {
            continue; // over the cap: drop the connection
        };
        let slot = if exempt(peer.ip()) {
            None
        } else {
            let mut m = per_addr.lock().unwrap();
            let n = m.entry(peer.ip()).or_default();
            if *n >= limits.per_address {
                continue;
            }
            *n += 1;
            Some(AddrSlot { map: per_addr.clone(), ip: peer.ip() })
        };
        let _ = stream.set_nodelay(true);
        let svc = app.clone().map_request(move |mut req: Request<Incoming>| {
            req.extensions_mut().insert(ConnectInfo(peer));
            req
        });
        let acceptor = acceptor.clone();
        let watcher = graceful.watcher();
        let limits = limits.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _slot = slot;
            // A TLS connection starts with a handshake record (0x16);
            // anything else is someone typing http://.
            let mut first = [0u8; 1];
            match tokio::time::timeout(limits.header_timeout, stream.peek(&mut first)).await {
                Ok(Ok(1)) if first[0] == 0x16 => {}
                Ok(Ok(1)) => {
                    redirect_to_https(stream, limits.header_timeout).await;
                    return;
                }
                _ => return,
            }
            let Ok(Ok(tls)) = tokio::time::timeout(limits.header_timeout, acceptor.accept(stream)).await else {
                return;
            };
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_timeout)
                .serve_connection(TokioIo::new(tls), TowerToHyperService::new(svc));
            let _ = tokio::time::timeout(limits.max_lifetime, watcher.watch(conn)).await;
        });
    }
    drop(listener);
    let _ = tokio::time::timeout(Duration::from_secs(5), graceful.shutdown()).await;
}

/// Answer a plain-HTTP request with a redirect to the same address over
/// HTTPS (or a 400 when the request doesn't name a sensible host). Nothing
/// else is ever sent over plain HTTP.
async fn redirect_to_https(mut stream: TcpStream, deadline: Duration) {
    let mut buf = Vec::with_capacity(1024);
    let read = async {
        let mut chunk = [0u8; 1024];
        while buf.len() < 8192 && !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    };
    if tokio::time::timeout(deadline, read).await.is_err() {
        return;
    }
    let resp = match https_location(&buf) {
        Some(loc) => format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        None => {
            let body = "pingrail only accepts HTTPS. Use https:// in the address.\n";
            format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.write_all(resp.as_bytes())).await;
    let _ = stream.shutdown().await;
}

/// The https:// address for a plain-HTTP request: same host and path.
fn https_location(req: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(req).ok()?;
    let mut lines = text.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let (_method, path) = (parts.next()?, parts.next()?);
    if !path.starts_with('/') || path.len() > 2048 || !path.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let host = lines
        .take_while(|l| !l.is_empty())
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v.trim()))?;
    let host_ok = !host.is_empty()
        && host.len() <= 255
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'));
    host_ok.then(|| format!("https://{host}{path}"))
}

/// Response headers that keep browsers strict, plus a deadline for every
/// request (reports get longer).
pub async fn harden(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let api = path.starts_with("/api/");
    // Reports take a while; so does a mail server that does not answer.
    let limit = if path.ends_with("/report") {
        180
    } else if path == "/api/alarms/test" {
        60
    } else {
        30
    };
    let mut resp = match tokio::time::timeout(Duration::from_secs(limit), next.run(req)).await {
        Ok(r) => r,
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({ "error": "The request took too long. Try a shorter time range." })),
        )
            .into_response(),
    };
    let html = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"));
    let h = resp.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), usb=(), payment=()"),
    );
    if html {
        // Sign-in and share pages are nobody's search result.
        h.insert("x-robots-tag", HeaderValue::from_static("noindex, nofollow"));
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; \
                 connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            ),
        );
    }
    if api {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

/// Parse a list of IPs / CIDRs ("127.0.0.1", "10.0.0.0/8").
pub fn parse_nets(list: &[String]) -> Vec<(IpAddr, u8)> {
    list.iter().filter_map(|s| crate::netpolicy::parse_cidr(s)).collect()
}

pub fn in_nets(ip: IpAddr, nets: &[(IpAddr, u8)]) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    nets.iter().any(|(n, b)| crate::netpolicy::in_cidr(ip, *n, *b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_gets_redirected_to_the_same_address() {
        let req = b"GET /s/abc?x=1 HTTP/1.1\r\nHost: pi.lan:8041\r\nAccept: */*\r\n\r\n";
        assert_eq!(https_location(req).as_deref(), Some("https://pi.lan:8041/s/abc?x=1"));
        let v6 = b"GET / HTTP/1.1\r\nhost: [fd00::7]:8040\r\n\r\n";
        assert_eq!(https_location(v6).as_deref(), Some("https://[fd00::7]:8040/"));
        // Header injection and junk hosts get a plain 400 instead.
        assert_eq!(https_location(b"GET / HTTP/1.1\r\nHost: evil.example\rLocation: x\r\n\r\n"), None);
        assert_eq!(https_location(b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n"), None);
        assert_eq!(https_location(b"GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n"), None);
        assert_eq!(https_location(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn trusted_proxy_lists() {
        let nets = parse_nets(&["127.0.0.1".into(), "::1".into(), "10.9.0.0/16".into(), "nonsense".into()]);
        assert_eq!(nets.len(), 3);
        assert!(in_nets("127.0.0.1".parse().unwrap(), &nets));
        assert!(in_nets("::ffff:127.0.0.1".parse().unwrap(), &nets));
        assert!(in_nets("10.9.200.1".parse().unwrap(), &nets));
        assert!(!in_nets("192.168.1.10".parse().unwrap(), &nets));
        assert!(!in_nets("127.0.0.2".parse().unwrap(), &nets));
    }
}

/// Whether the browser takes gzip (`Accept-Encoding`, honouring `q=0`).
pub fn takes_gzip(h: &HeaderMap) -> bool {
    h.get_all(header::ACCEPT_ENCODING).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).any(|part| {
        let mut it = part.split(';');
        let name = it.next().unwrap_or("").trim();
        let off = it.any(|p| {
            let p = p.trim();
            p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")).is_some_and(|q| q.parse::<f32>().is_ok_and(|q| q == 0.0))
        });
        name.eq_ignore_ascii_case("gzip") && !off
    })
}

fn gzip_bytes(data: &[u8], level: flate2::Compression) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::with_capacity(data.len() / 4 + 64), level);
    // Writing to a Vec can't fail.
    let _ = enc.write_all(data);
    enc.finish().unwrap_or_default()
}

/// A page, script or stylesheet kept ready in plain and gzip form, with a
/// tag of its contents so a browser that already has it is told so (304)
/// instead of being sent it again.
pub struct Packed {
    raw: &'static str,
    gz: &'static [u8],
    etag: HeaderValue,
}

/// The packed form of a built-in text file, made on first use. Only ever
/// called with the handful of files built into the program.
pub fn packed(body: &'static str) -> &'static Packed {
    static ALL: Mutex<Vec<&'static Packed>> = Mutex::new(Vec::new());
    let mut all = ALL.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = all.iter().find(|p| std::ptr::eq(p.raw, body)) {
        return p;
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, body.as_bytes());
    let tag: String = digest.as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect();
    let p: &'static Packed = Box::leak(Box::new(Packed {
        raw: body,
        gz: Box::leak(gzip_bytes(body.as_bytes(), flate2::Compression::best()).into_boxed_slice()),
        etag: HeaderValue::from_str(&format!("\"{tag}\"")).unwrap_or(HeaderValue::from_static("\"0\"")),
    }));
    all.push(p);
    p
}

impl Packed {
    /// The response for a request with these headers. `revalidate` is for
    /// files a browser may keep and check (scripts, styles); pages that must
    /// be fetched every time pass false.
    pub fn response(&self, req: &HeaderMap, ctype: &'static str, revalidate: bool) -> Response {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
        h.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static(if revalidate { "no-cache" } else { "no-store" }));
        if revalidate {
            h.insert(header::ETAG, self.etag.clone());
            let have = req.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()).unwrap_or("");
            let tag = self.etag.to_str().unwrap_or("");
            if have.split(',').any(|t| t.trim().trim_start_matches("W/") == tag) {
                return (StatusCode::NOT_MODIFIED, h).into_response();
            }
        }
        if takes_gzip(req) && self.gz.len() < self.raw.len() {
            h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
            (h, self.gz).into_response()
        } else {
            (h, self.raw).into_response()
        }
    }
}

/// gzip for the large JSON answers (overview and detail), which a browser
/// with the page open fetches every second or so. Those carry measurements
/// only, never a token or session secret, so compressing them gives nothing
/// away through their size. Sign-in and settings answers are not compressed.
pub async fn gzip_json(req: Request, next: Next) -> Response {
    let wants = takes_gzip(req.headers());
    let resp = next.run(req).await;
    if !wants || resp.status() != StatusCode::OK || resp.headers().contains_key(header::CONTENT_ENCODING) {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 256 * 1024 * 1024).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    parts.headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    if bytes.len() < 1024 {
        return Response::from_parts(parts, axum::body::Body::from(bytes));
    }
    let gz = gzip_bytes(&bytes, flate2::Compression::fast());
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    Response::from_parts(parts, axum::body::Body::from(gz))
}

#[cfg(test)]
mod pack_tests {
    use super::*;
    use std::io::Read;

    fn headers(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(k.clone(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn gzip_only_when_the_browser_takes_it() {
        assert!(takes_gzip(&headers(&[(header::ACCEPT_ENCODING, "gzip, deflate, br")])));
        assert!(takes_gzip(&headers(&[(header::ACCEPT_ENCODING, "br;q=1.0, GZIP;q=0.5")])));
        assert!(!takes_gzip(&headers(&[(header::ACCEPT_ENCODING, "gzip;q=0, br")])));
        assert!(!takes_gzip(&headers(&[(header::ACCEPT_ENCODING, "br, identity")])));
        assert!(!takes_gzip(&HeaderMap::new()));
    }

    #[tokio::test]
    async fn packed_file_round_trips_and_answers_not_modified() {
        static BODY: &str = "body { color: red; } /* padding padding padding padding padding padding padding padding */";
        let p = packed(BODY);
        assert!(std::ptr::eq(p, packed(BODY)), "made once");

        let plain = p.response(&HeaderMap::new(), "text/css", true);
        assert!(plain.headers().get(header::CONTENT_ENCODING).is_none());
        let etag = plain.headers().get(header::ETAG).unwrap().to_str().unwrap().to_string();
        let body = axum::body::to_bytes(plain.into_body(), 1 << 20).await.unwrap();
        assert_eq!(body, BODY.as_bytes());

        let gz = p.response(&headers(&[(header::ACCEPT_ENCODING, "gzip")]), "text/css", true);
        assert_eq!(gz.headers().get(header::CONTENT_ENCODING).unwrap(), "gzip");
        assert_eq!(gz.headers().get(header::VARY).unwrap(), "accept-encoding");
        let body = axum::body::to_bytes(gz.into_body(), 1 << 20).await.unwrap();
        let mut out = String::new();
        flate2::read::GzDecoder::new(&body[..]).read_to_string(&mut out).unwrap();
        assert_eq!(out, BODY);

        let same = p.response(&headers(&[(header::IF_NONE_MATCH, &etag)]), "text/css", true);
        assert_eq!(same.status(), StatusCode::NOT_MODIFIED);
        let other = p.response(&headers(&[(header::IF_NONE_MATCH, "\"nope\"")]), "text/css", true);
        assert_eq!(other.status(), StatusCode::OK);

        // A page that must be fetched every time carries no tag to check.
        let page = p.response(&headers(&[(header::IF_NONE_MATCH, &etag)]), "text/html", false);
        assert_eq!(page.status(), StatusCode::OK);
        assert!(page.headers().get(header::ETAG).is_none());
        assert_eq!(page.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
    }
}

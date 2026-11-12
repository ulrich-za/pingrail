//! Sending alarm emails: a small SMTP submission client.
//!
//! Mail only ever leaves over TLS, either from the first byte (port 465) or
//! after STARTTLS (port 587), with the server's certificate checked against
//! the system's trust store. Messages are plain text. Everything that ends
//! up in a header is checked or encoded first, so a target's name can never
//! add a header or a recipient of its own.

use std::time::Duration;

use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// How the connection to the mail server is encrypted.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS from the start (port 465).
    #[default]
    Tls,
    /// Plain greeting, then STARTTLS before anything else is said (port 587).
    Starttls,
}

impl Security {
    pub fn default_port(self) -> u16 {
        match self {
            Security::Tls => 465,
            Security::Starttls => 587,
        }
    }
}

/// The mail server alarm emails go through. The password is kept apart, in
/// a file only the service can read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct MailServer {
    pub host: String,
    /// 0 = the usual port for `security`.
    pub port: u16,
    pub security: Security,
    pub username: String,
    /// `Name <address>` or just an address.
    pub from: String,
}

impl MailServer {
    pub fn port(&self) -> u16 {
        if self.port == 0 { self.security.default_port() } else { self.port }
    }

    /// Enough is filled in to try sending.
    pub fn ready(&self) -> bool {
        valid_host(&self.host) && parse_from(&self.from).is_some()
    }
}

/// Why an email did not go out, in words for whoever set the mail server up.
#[derive(Debug, Clone, PartialEq)]
pub struct MailError {
    pub text: String,
    /// Worth trying again later (the server or the line may be down); false
    /// when the settings themselves are refused.
    pub temporary: bool,
}

impl MailError {
    fn soft(text: impl Into<String>) -> MailError {
        MailError { text: text.into(), temporary: true }
    }

    fn hard(text: impl Into<String>) -> MailError {
        MailError { text: text.into(), temporary: false }
    }
}

impl std::fmt::Display for MailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

type Result<T> = std::result::Result<T, MailError>;

// ----- what may go where ----------------------------------------------------

/// A host name or address a mail server can be reached at.
pub fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
}

/// An email address plain enough to put in a header and an SMTP command as
/// it is: ASCII, no spaces, brackets, quotes or control characters.
pub fn valid_address(a: &str) -> bool {
    let Some((local, domain)) = a.split_once('@') else { return false };
    a.len() <= 254
        && !local.is_empty()
        && local.len() <= 64
        && local.chars().all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+/=?^_`{|}~.-".contains(c))
        && !domain.is_empty()
        && !domain.starts_with(['.', '-'])
        && !domain.ends_with(['.', '-'])
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

/// `Name <address>` or a bare address, as (name, address).
pub fn parse_from(from: &str) -> Option<(Option<String>, String)> {
    let from = from.trim();
    let (name, addr) = match from.rsplit_once('<') {
        Some((name, rest)) => (name.trim().trim_matches('"').trim(), rest.strip_suffix('>')?.trim()),
        None => ("", from),
    };
    if !valid_address(addr) {
        return None;
    }
    let name = crate::util::clean_text(name, 80);
    Some(((!name.is_empty()).then_some(name), addr.to_string()))
}

/// Split what was typed into the recipients box: addresses separated by
/// commas, semicolons or spaces. Returns the addresses, or the first entry
/// that is not one.
pub fn parse_recipients(s: &str) -> std::result::Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for part in s.split([',', ';', ' ', '\n', '\t']).map(str::trim).filter(|p| !p.is_empty()) {
        if !valid_address(part) {
            return Err(part.chars().take(80).collect());
        }
        if !out.iter().any(|a| a.eq_ignore_ascii_case(part)) {
            out.push(part.to_string());
        }
    }
    Ok(out)
}

// ----- the message ------------------------------------------------------------

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        out.push(T[(b[0] >> 2) as usize] as char);
        out.push(T[((b[0] & 3) << 4 | b[1] >> 4) as usize] as char);
        out.push(if chunk.len() > 1 { T[((b[1] & 15) << 2 | b[2] >> 6) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(b[2] & 63) as usize] as char } else { '=' });
    }
    out
}

/// Text for a header: control characters (line breaks above all) removed.
fn header_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect::<String>().trim().to_string()
}

/// A header value that may hold any text: as it is when plain ASCII, as
/// RFC 2047 encoded words otherwise, folded so no line runs long.
fn encoded(s: &str) -> String {
    let s = header_text(s);
    if s.is_ascii() && s.len() <= 200 {
        return s;
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for ch in s.chars() {
        // 39 bytes make 52 base64 characters: a word of 64 with its
        // wrapping, which fits a line behind any header's name.
        if chunk.len() + ch.len_utf8() > 39 {
            words.push(format!("=?UTF-8?B?{}?=", base64(chunk.as_bytes())));
            chunk.clear();
        }
        chunk.push(ch);
    }
    if !chunk.is_empty() {
        words.push(format!("=?UTF-8?B?{}?=", base64(chunk.as_bytes())));
    }
    words.join("\r\n ")
}

/// The `From` header for a name and address.
fn mailbox(name: Option<&str>, addr: &str) -> String {
    match name.map(header_text).filter(|n| !n.is_empty()) {
        None => addr.to_string(),
        Some(n) if n.is_ascii() => format!("\"{}\" <{addr}>", n.replace('\\', "").replace('"', "'")),
        Some(n) => format!("{} <{addr}>", encoded(&n)),
    }
}

/// The whole message, headers and body, with CRLF line ends, ready for DATA
/// (not yet dot-stuffed).
fn build(from: (Option<&str>, &str), to: &[String], subject: &str, body: &str, when: chrono::DateTime<chrono::FixedOffset>, id: &str) -> String {
    let domain = from.1.rsplit_once('@').map_or("localhost", |(_, d)| d);
    let mut m = String::new();
    m.push_str(&format!("From: {}\r\n", mailbox(from.0, from.1)));
    // One address a line, so the header never runs long.
    m.push_str(&format!("To: {}\r\n", to.join(",\r\n ")));
    m.push_str(&format!("Subject: {}\r\n", encoded(subject)));
    m.push_str(&format!("Date: {}\r\n", when.to_rfc2822()));
    m.push_str(&format!("Message-ID: <{id}@{domain}>\r\n"));
    m.push_str("MIME-Version: 1.0\r\n");
    m.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    // Sent by a machine: mail systems should not answer it automatically.
    m.push_str("Auto-Submitted: auto-generated\r\n");
    let lines: Vec<&str> = body.lines().collect();
    if body.is_ascii() && lines.iter().all(|l| l.len() <= 900) && !body.chars().any(|c| c.is_control() && c != '\n' && c != '\r') {
        m.push_str("Content-Transfer-Encoding: 7bit\r\n\r\n");
        for l in lines {
            m.push_str(l);
            m.push_str("\r\n");
        }
    } else {
        m.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        let b = base64(lines.join("\r\n").as_bytes());
        for chunk in b.as_bytes().chunks(76) {
            m.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            m.push_str("\r\n");
        }
    }
    m
}

// ----- the conversation with the server -------------------------------------------

/// Longest reply line and most reply lines read before giving up on a server.
const MAX_LINE: u64 = 2000;
const MAX_LINES: usize = 100;
/// How long a server gets to answer one command, and the whole exchange.
const REPLY_WITHIN: Duration = Duration::from_secs(12);
const SEND_WITHIN: Duration = Duration::from_secs(45);

struct Conn<S> {
    io: BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    fn new(s: S) -> Conn<S> {
        Conn { io: BufReader::new(s) }
    }

    /// One reply: its code and its text (lines joined), however many lines
    /// the server spreads it over. A server that says nothing for a while
    /// is usually one spoken to on the wrong port or the wrong way.
    async fn reply(&mut self) -> Result<(u16, String)> {
        match tokio::time::timeout(REPLY_WITHIN, self.read_reply()).await {
            Ok(r) => r,
            Err(_) => Err(MailError::soft("The mail server did not answer. Check the port and the kind of connection: TLS is usually port 465, STARTTLS port 587.")),
        }
    }

    async fn read_reply(&mut self) -> Result<(u16, String)> {
        let mut text = String::new();
        for _ in 0..MAX_LINES {
            let mut line = Vec::new();
            let n = (&mut self.io)
                .take(MAX_LINE + 1)
                .read_until(b'\n', &mut line)
                .await
                .map_err(|e| MailError::soft(format!("The connection to the mail server broke: {e}.")))?;
            if n == 0 {
                return Err(MailError::soft("The mail server closed the connection."));
            }
            if line.last() != Some(&b'\n') {
                return Err(MailError::soft("The mail server sent something that is not a mail reply."));
            }
            let line = String::from_utf8_lossy(&line);
            let line = line.trim_end();
            let code: u16 = line.get(..3).and_then(|c| c.parse().ok()).ok_or_else(|| MailError::soft("The mail server sent something that is not a mail reply."))?;
            let rest = line.get(4..).unwrap_or("");
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(rest);
            if line.as_bytes().get(3) != Some(&b'-') {
                return Ok((code, text));
            }
        }
        Err(MailError::soft("The mail server's reply went on too long."))
    }

    async fn write(&mut self, data: &[u8]) -> Result<()> {
        let io = self.io.get_mut();
        io.write_all(data).await.map_err(|e| MailError::soft(format!("The connection to the mail server broke: {e}.")))?;
        io.flush().await.map_err(|e| MailError::soft(format!("The connection to the mail server broke: {e}.")))
    }

    /// Send one command line and read the reply.
    async fn cmd(&mut self, line: &str) -> Result<(u16, String)> {
        debug_assert!(!line.contains(['\r', '\n']));
        self.write(format!("{line}\r\n").as_bytes()).await?;
        self.reply().await
    }
}

/// A server's words, short enough and clean enough to show.
fn said(code: u16, text: &str) -> String {
    let t: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(200).collect();
    format!("{code} {}", t.trim())
}

fn refused(what: &str, code: u16, text: &str) -> MailError {
    let e = format!("{what}: the mail server answered “{}”.", said(code, text));
    // 4xx is "not now"; 5xx is "no".
    if (400..500).contains(&code) { MailError::soft(e) } else { MailError::hard(e) }
}

fn helo_name(name: &str) -> String {
    let n: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')).collect();
    let n = n.trim_matches(['.', '-']).to_string();
    if n.is_empty() { "localhost".into() } else { n }
}

/// EHLO, and what the server says it can do (upper case, one per line).
async fn ehlo<S: AsyncRead + AsyncWrite + Unpin>(c: &mut Conn<S>, helo: &str) -> Result<Vec<String>> {
    let (code, text) = c.cmd(&format!("EHLO {}", helo_name(helo))).await?;
    if code != 250 {
        return Err(refused("The greeting was refused", code, &text));
    }
    Ok(text.lines().skip(1).map(|l| l.trim().to_ascii_uppercase()).collect())
}

/// Everything after the connection is encrypted: sign in, hand the message
/// over, say goodbye.
async fn submit<S: AsyncRead + AsyncWrite + Unpin>(
    c: &mut Conn<S>,
    helo: &str,
    username: &str,
    password: Option<&str>,
    from: &str,
    to: &[String],
    message: &str,
) -> Result<()> {
    let caps = ehlo(c, helo).await?;
    if !username.is_empty() {
        let password = password.unwrap_or_default();
        if username.contains(['\0', '\r', '\n']) || password.contains(['\0', '\r', '\n']) {
            return Err(MailError::hard("The username or password holds characters a mail server cannot take."));
        }
        let mechs = caps.iter().find_map(|l| l.strip_prefix("AUTH ").or_else(|| l.strip_prefix("AUTH="))).unwrap_or_default();
        let has = |m: &str| mechs.split_whitespace().any(|x| x == m);
        let (code, text) = if has("PLAIN") {
            c.cmd(&format!("AUTH PLAIN {}", base64(format!("\0{username}\0{password}").as_bytes()))).await?
        } else if has("LOGIN") {
            let (code, text) = c.cmd("AUTH LOGIN").await?;
            if code != 334 {
                return Err(refused("Signing in was refused", code, &text));
            }
            let (code, text) = c.cmd(&base64(username.as_bytes())).await?;
            if code != 334 {
                return Err(refused("Signing in was refused", code, &text));
            }
            c.cmd(&base64(password.as_bytes())).await?
        } else {
            return Err(MailError::hard("The mail server offers no way of signing in that pingrail knows (it needs PLAIN or LOGIN)."));
        };
        if code != 235 {
            return Err(refused("The username or password was refused", code, &text));
        }
    }
    let (code, text) = c.cmd(&format!("MAIL FROM:<{from}>")).await?;
    if code != 250 {
        return Err(refused(&format!("The sender {from} was refused"), code, &text));
    }
    for rcpt in to {
        let (code, text) = c.cmd(&format!("RCPT TO:<{rcpt}>")).await?;
        if !(250..=252).contains(&code) {
            return Err(refused(&format!("The address {rcpt} was refused"), code, &text));
        }
    }
    let (code, text) = c.cmd("DATA").await?;
    if code != 354 {
        return Err(refused("The message was refused", code, &text));
    }
    // A line that starts with a dot gets a second one, so that none of the
    // message can be read as its end.
    let mut data = String::with_capacity(message.len() + 16);
    for line in message.split_inclusive("\r\n") {
        if line.starts_with('.') {
            data.push('.');
        }
        data.push_str(line);
    }
    if !data.ends_with("\r\n") {
        data.push_str("\r\n");
    }
    data.push_str(".\r\n");
    c.write(data.as_bytes()).await?;
    let (code, text) = c.reply().await?;
    if code != 250 {
        return Err(refused("The message was refused", code, &text));
    }
    // The message is the server's now; a goodbye that goes wrong changes nothing.
    let _ = c.cmd("QUIT").await;
    Ok(())
}

/// One email to hand to the server.
pub struct Email<'a> {
    pub to: &'a [String],
    pub subject: &'a str,
    pub body: &'a str,
}

/// Send `mail` through `server`. `helo` is this machine's name.
pub async fn send(server: &MailServer, password: Option<&str>, helo: &str, mail: Email<'_>) -> Result<()> {
    if !valid_host(&server.host) {
        return Err(MailError::hard("No mail server is set."));
    }
    let Some((name, from)) = parse_from(&server.from) else {
        return Err(MailError::hard("The From address is not an email address."));
    };
    if mail.to.is_empty() || !mail.to.iter().all(|a| valid_address(a)) {
        return Err(MailError::hard("There is no address to send to."));
    }
    let when = chrono::Local::now().fixed_offset();
    let message = build((name.as_deref(), &from), mail.to, mail.subject, mail.body, when, &crate::config::random_hex(16));
    let work = deliver(server, password, helo, &from, mail.to, &message);
    match tokio::time::timeout(SEND_WITHIN, work).await {
        Ok(r) => r,
        Err(_) => Err(MailError::soft(format!("{} took too long to answer.", server.host))),
    }
}

async fn deliver(server: &MailServer, password: Option<&str>, helo: &str, from: &str, to: &[String], message: &str) -> Result<()> {
    let (host, port) = (server.host.as_str(), server.port());
    let tcp = match tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(MailError::soft(format!("Could not connect to {host} on port {port}: {e}."))),
        Err(_) => return Err(MailError::soft(format!("{host} did not answer on port {port}."))),
    };
    let _ = tcp.set_nodelay(true);
    // The system's trust store decides whether the server is who it says.
    let (tls, _) = crate::tls::client_config(Vec::new());
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls));
    let name = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_string()).map_err(|_| MailError::hard(format!("{host} is not a host name.")))?,
    };
    let secure = |e: std::io::Error| MailError::soft(format!("Could not make an encrypted connection to {host}: {e}. pingrail does not send mail without one."));
    let slow = || MailError::soft(format!("{host} did not finish setting up an encrypted connection. Check the port and the kind of connection: TLS is usually port 465, STARTTLS port 587."));
    match server.security {
        Security::Tls => {
            let stream = tokio::time::timeout(REPLY_WITHIN, connector.connect(name, tcp)).await.map_err(|_| slow())?.map_err(secure)?;
            let mut c = Conn::new(stream);
            let (code, text) = c.reply().await?;
            if code != 220 {
                return Err(refused("The mail server is not taking mail", code, &text));
            }
            submit(&mut c, helo, &server.username, password, from, to, message).await
        }
        Security::Starttls => {
            let mut c = Conn::new(tcp);
            let (code, text) = c.reply().await?;
            if code != 220 {
                return Err(refused("The mail server is not taking mail", code, &text));
            }
            let caps = ehlo(&mut c, helo).await?;
            if !caps.iter().any(|l| l == "STARTTLS") {
                return Err(MailError::hard(format!("{host} does not offer STARTTLS on port {port}. pingrail does not send mail unencrypted.")));
            }
            let (code, text) = c.cmd("STARTTLS").await?;
            if code != 220 {
                return Err(refused("STARTTLS was refused", code, &text));
            }
            // Anything already waiting was sent before encryption began and
            // must not be taken as part of what follows.
            if !c.io.buffer().is_empty() {
                return Err(MailError::soft("The mail server sent data before the encrypted connection began."));
            }
            let stream = tokio::time::timeout(REPLY_WITHIN, connector.connect(name, c.io.into_inner())).await.map_err(|_| slow())?.map_err(secure)?;
            let mut c = Conn::new(stream);
            submit(&mut c, helo, &server.username, password, from, to, message).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_senders() {
        assert!(valid_address("ulrich@example.com") && valid_address("a.b+alarms@mail.example.co.za"));
        for bad in ["", "nobody", "a@", "@b.com", "a b@c.com", "a@b.com\r\nBcc: x@y.z", "a@b,c.com", "<a@b.com>", "a@-b.com", "ü@b.com", "a@b.com."] {
            assert!(!valid_address(bad), "{bad:?}");
        }
        assert_eq!(parse_from("pingrail on office-pc <alarms@example.com>"), Some((Some("pingrail on office-pc".into()), "alarms@example.com".into())));
        assert_eq!(parse_from(" alarms@example.com "), Some((None, "alarms@example.com".into())));
        assert_eq!(parse_from("\"Alarms\" <alarms@example.com>"), Some((Some("Alarms".into()), "alarms@example.com".into())));
        assert_eq!(parse_from("x <not an address>"), None);
        assert_eq!(parse_from("x <a@b.com> trailing"), None);
        assert_eq!(parse_recipients("a@b.com, c@d.com;e@f.com  A@B.com"), Ok(vec!["a@b.com".to_string(), "c@d.com".into(), "e@f.com".into()]));
        assert_eq!(parse_recipients("a@b.com, nope"), Err("nope".to_string()));
        assert_eq!(parse_recipients("  "), Ok(vec![]));
        assert!(valid_host("smtp.example.com") && valid_host("192.0.2.25") && !valid_host("smtp example") && !valid_host("a/b") && !valid_host(""));
    }

    #[test]
    fn base64_matches_the_standard() {
        for (plain, enc) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(base64(plain.as_bytes()), enc);
        }
        assert_eq!(base64("\0user\0pass".as_bytes()), "AHVzZXIAcGFzcw==");
    }

    fn when() -> chrono::DateTime<chrono::FixedOffset> {
        use chrono::TimeZone;
        chrono::FixedOffset::east_opt(7200).unwrap().with_ymd_and_hms(2026, 11, 11, 15, 12, 0).unwrap()
    }

    #[test]
    fn a_plain_message() {
        let to = vec!["ulrich@example.com".to_string(), "office@example.com".to_string()];
        let m = build((Some("pingrail on office-pc"), "alarms@example.com"), &to, "[pingrail] Printer is not answering", "Line one\n.starts with a dot\n\nLast", when(), "abc");
        assert_eq!(
            m,
            "From: \"pingrail on office-pc\" <alarms@example.com>\r\n\
             To: ulrich@example.com,\r\n office@example.com\r\n\
             Subject: [pingrail] Printer is not answering\r\n\
             Date: Wed, 11 Nov 2026 15:12:00 +0200\r\n\
             Message-ID: <abc@example.com>\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Auto-Submitted: auto-generated\r\n\
             Content-Transfer-Encoding: 7bit\r\n\
             \r\n\
             Line one\r\n.starts with a dot\r\n\r\nLast\r\n"
        );
    }

    #[test]
    fn names_cannot_add_headers() {
        // A target called this must not get a Bcc of its own.
        let evil = "Printer\r\nBcc: thief@example.net\r\n\r\nNew body";
        let to = vec!["ulrich@example.com".to_string()];
        let m = build((Some("pingrail\r\nBcc: x@y.z"), "alarms@example.com"), &to, &format!("[pingrail] {evil} is not answering"), "Body", when(), "id");
        let head = m.split("\r\n\r\n").next().unwrap();
        assert_eq!(head.lines().filter(|l| l.to_ascii_lowercase().starts_with("bcc")).count(), 0);
        assert!(head.contains("Subject: [pingrail] PrinterBcc: thief@example.netNew body is not answering\r\n"));
        assert!(head.starts_with("From: \"pingrailBcc: x@y.z\" <alarms@example.com>\r\n"));
        assert_eq!(m.matches("\r\n\r\n").count(), 1);
    }

    #[test]
    fn other_scripts_are_encoded() {
        let to = vec!["ulrich@example.com".to_string()];
        let m = build((Some("Büro"), "alarms@example.com"), &to, "[pingrail] Офис Москва 東京 オフィス is not answering", "Офис Москва не отвечает\nline two", when(), "id");
        assert!(m.is_ascii());
        assert!(m.contains("From: =?UTF-8?B?QsO8cm8=?= <alarms@example.com>\r\n"));
        let subject: String = m.lines().skip_while(|l| !l.starts_with("Subject: ")).take_while(|l| l.starts_with("Subject: ") || l.starts_with(' ')).collect();
        assert!(subject.matches("=?UTF-8?B?").count() >= 2 && m.lines().all(|l| l.len() <= 78));
        assert!(m.contains("Content-Transfer-Encoding: base64\r\n\r\n"));
    }

    /// A mail server that follows a script: for each step, the line it
    /// expects to start with what is given, and what it answers.
    async fn script(steps: Vec<(&'static str, &'static str)>, greet: bool) -> (Conn<tokio::io::DuplexStream>, tokio::task::JoinHandle<Vec<String>>) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let mut io = BufReader::new(server);
            let mut seen = Vec::new();
            if greet {
                io.get_mut().write_all(b"220 mail.example.com ESMTP\r\n").await.unwrap();
            }
            for (expect, answer) in steps {
                let mut got = String::new();
                if expect == "<data>" {
                    loop {
                        let mut line = String::new();
                        if io.read_line(&mut line).await.unwrap() == 0 || line == ".\r\n" {
                            break;
                        }
                        got.push_str(&line);
                    }
                } else {
                    io.read_line(&mut got).await.unwrap();
                    assert!(got.starts_with(expect), "expected {expect:?}, got {got:?}");
                }
                seen.push(got);
                io.get_mut().write_all(answer.as_bytes()).await.unwrap();
            }
            seen
        });
        (Conn::new(client), task)
    }

    #[tokio::test]
    async fn a_message_is_handed_over() {
        let (mut c, server) = script(
            vec![
                ("EHLO office-pc", "250-mail.example.com\r\n250-SIZE 1000000\r\n250 AUTH LOGIN PLAIN\r\n"),
                ("AUTH PLAIN AGFsYXJtc0BleGFtcGxlLmNvbQBzM2NyZXQ=", "235 2.7.0 Accepted\r\n"),
                ("MAIL FROM:<alarms@example.com>", "250 OK\r\n"),
                ("RCPT TO:<ulrich@example.com>", "250 OK\r\n"),
                ("RCPT TO:<office@example.com>", "251 will forward\r\n"),
                ("DATA", "354 go on\r\n"),
                ("<data>", "250 queued as 1\r\n"),
                ("QUIT", "221 bye\r\n"),
            ],
            false,
        )
        .await;
        let to = vec!["ulrich@example.com".to_string(), "office@example.com".to_string()];
        submit(&mut c, "office-pc", "alarms@example.com", Some("s3cret"), "alarms@example.com", &to, "Subject: x\r\n\r\nfirst\r\n.second\r\n..third\r\n").await.unwrap();
        let seen = server.await.unwrap();
        // The dots at the start of lines arrive doubled.
        assert_eq!(seen[6], "Subject: x\r\n\r\nfirst\r\n..second\r\n...third\r\n");
    }

    #[tokio::test]
    async fn refusals_are_told_apart() {
        // A wrong password is the settings' fault: no point trying again.
        let (mut c, _s) = script(vec![("EHLO", "250-x\r\n250 AUTH PLAIN\r\n"), ("AUTH PLAIN", "535 5.7.8 Bad credentials\r\n")], false).await;
        let e = submit(&mut c, "h", "u", Some("p"), "a@b.com", &["c@d.com".to_string()], "x\r\n").await.unwrap_err();
        assert!(!e.temporary && e.text.contains("username or password was refused") && e.text.contains("535 5.7.8 Bad credentials"));
        // A full mailbox may clear: worth another try.
        let (mut c, _s) = script(vec![("EHLO", "250 x\r\n"), ("MAIL FROM", "250 ok\r\n"), ("RCPT TO", "452 4.2.2 Mailbox full\r\n")], false).await;
        let e = submit(&mut c, "h", "", None, "a@b.com", &["c@d.com".to_string()], "x\r\n").await.unwrap_err();
        assert!(e.temporary && e.text.contains("c@d.com was refused"));
        // No way of signing in that is understood.
        let (mut c, _s) = script(vec![("EHLO", "250-x\r\n250 AUTH CRAM-MD5\r\n")], false).await;
        let e = submit(&mut c, "h", "u", Some("p"), "a@b.com", &["c@d.com".to_string()], "x\r\n").await.unwrap_err();
        assert!(!e.temporary && e.text.contains("PLAIN or LOGIN"));
        // LOGIN, for servers that only have that.
        let (mut c, s) = script(
            vec![("EHLO", "250-x\r\n250 AUTH LOGIN\r\n"), ("AUTH LOGIN", "334 VXNlcm5hbWU6\r\n"), ("dQ==", "334 UGFzc3dvcmQ6\r\n"), ("cA==", "235 ok\r\n"), ("MAIL", "550 5.7.1 Not allowed\r\n")],
            false,
        )
        .await;
        let e = submit(&mut c, "h", "u", Some("p"), "a@b.com", &["c@d.com".to_string()], "x\r\n").await.unwrap_err();
        assert!(!e.temporary && e.text.contains("sender a@b.com was refused"));
        assert_eq!(s.await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn a_server_that_talks_nonsense() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = server.write_all(&vec![b'x'; 5000]).await;
        });
        let mut c = Conn::new(client);
        assert!(c.reply().await.unwrap_err().text.contains("not a mail reply"));
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            for _ in 0..200 {
                let _ = server.write_all(b"250-more\r\n").await;
            }
        });
        let mut c = Conn::new(client);
        assert!(c.reply().await.unwrap_err().text.contains("too long"));
        assert_eq!(helo_name("office pc!.example"), "officepc.example");
        assert_eq!(helo_name("///"), "localhost");
    }
}

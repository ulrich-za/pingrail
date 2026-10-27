//! The admin UI and the share-link pages come from the same sources
//! (web/index.html and web/app.js), cut apart at start-up so that each page
//! carries only the markup and code its audience can use: visitors never
//! receive the sign-in view, password or share-link dialogs, or the code
//! behind them; a view-only link gets no add, edit or remove controls; a link
//! without reports gets no export dialog; and the admin page carries nothing
//! that only visitors use.
//!
//! Regions are marked `<!--@tag-->…<!--@end-->` in HTML and
//! `/*@tag*/…/*@end*/` in JavaScript, and may nest. Tags:
//! - `admin`: the signed-in owner's page;
//! - `share`: share-link pages;
//! - `add`: adding, editing and removing destinations (the owner always;
//!   visitors when their link allows adding);
//! - `export`: PDF/PNG reports (the owner always; visitors when allowed).
//!
//! A region is kept when every tag around it is wanted. Unmarked text goes
//! to every page.

use std::sync::OnceLock;

const INDEX_HTML: &str = include_str!("web/index.html");
const APP_JS: &str = include_str!("web/app.js");
const STATUS_HTML: &str = include_str!("web/status.html");

#[cfg(test)]
const TAGS: [&str; 4] = ["admin", "share", "add", "export"];

/// What a share link lets its visitors do, as far as the page is concerned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Visitor {
    pub add: bool,
    pub export: bool,
}

impl Visitor {
    fn index(self) -> usize {
        usize::from(self.add) | (usize::from(self.export) << 1)
    }
    const ALL: [Visitor; 4] = [
        Visitor { add: false, export: false },
        Visitor { add: true, export: false },
        Visitor { add: false, export: true },
        Visitor { add: true, export: true },
    ];
    fn tags(self) -> Vec<&'static str> {
        let mut t = vec!["share"];
        if self.add {
            t.push("add");
        }
        if self.export {
            t.push("export");
        }
        t
    }
    /// The script's address for this kind of link.
    pub fn script_path(self) -> &'static str {
        match (self.add, self.export) {
            (false, false) => "/share.js",
            (true, false) => "/share-add.js",
            (false, true) => "/share-export.js",
            (true, true) => "/share-add-export.js",
        }
    }
}

pub struct Pages {
    pub admin_html: String,
    pub admin_js: String,
    share_html: [String; 4],
    share_js: [String; 4],
}

impl Pages {
    pub fn share_html(&self, v: Visitor) -> &str {
        &self.share_html[v.index()]
    }
    pub fn share_js(&self, v: Visitor) -> &str {
        &self.share_js[v.index()]
    }
}

pub fn pages() -> &'static Pages {
    static P: OnceLock<Pages> = OnceLock::new();
    P.get_or_init(|| {
        let admin = ["admin", "add", "export"];
        Pages {
            admin_html: with_about(&cut(INDEX_HTML, HTML, &admin)),
            admin_js: cut(APP_JS, JS, &admin),
            share_html: Visitor::ALL.map(|v| with_about(&cut(INDEX_HTML, HTML, &v.tags())).replace("/share.js", v.script_path())),
            share_js: Visitor::ALL.map(|v| cut(APP_JS, JS, &v.tags())),
        }
    })
}

/// The About dialog's details, written into the page.
fn with_about(html: &str) -> String {
    use crate::server::about;
    [
        ("{{about.name}}", about::NAME),
        ("{{about.version}}", about::VERSION),
        ("{{about.publisher}}", about::PUBLISHER),
        ("{{about.copyright}}", about::COPYRIGHT),
        ("{{about.license}}", about::LICENSE),
        ("{{about.notice}}", about::WARRANTY),
        ("{{about.trademark}}", about::TRADEMARK),
        ("{{about.contact}}", about::CONTACT),
    ]
    .iter()
    .fold(html.to_string(), |page, (key, value)| page.replace(key, &esc(value)))
}

/// Marker syntax: (opening, closing) around the tag.
type Syntax = (&'static str, &'static str);
const HTML: Syntax = ("<!--@", "-->");
const JS: Syntax = ("/*@", "*/");

/// The text for a page that wants `keep`: unmarked text, plus regions whose
/// every enclosing tag is wanted. A marker alone on its line takes the line
/// with it.
fn cut(src: &str, (open, close): Syntax, keep: &[&str]) -> String {
    let mut out = String::with_capacity(src.len());
    // Enclosing tags; a region is dropped while any of them isn't wanted.
    let mut stack: Vec<bool> = Vec::new();
    let dropping = |s: &[bool]| s.iter().any(|kept| !kept);
    let mut pos = 0; // start of the text not yet copied or skipped
    while let Some(rel) = src[pos..].find(open) {
        let i = pos + rel;
        let Some(len) = src[i + open.len()..].find(close) else { break };
        let tag = &src[i + open.len()..i + open.len() + len];
        let mut end = i + open.len() + len + close.len();
        // Alone on its line (only spaces before it, a line break after it):
        // the whole line goes.
        let line_start = src[..i].rfind('\n').map_or(0, |p| p + 1);
        let alone = src[line_start..i].trim().is_empty() && (src[end..].starts_with('\n') || end == src.len());
        if !dropping(&stack) {
            out.push_str(&src[pos..if alone { line_start.max(pos) } else { i }]);
        }
        if alone && end < src.len() {
            end += 1;
        }
        if tag == "end" {
            stack.pop();
        } else {
            stack.push(keep.contains(&tag));
        }
        pos = end;
    }
    if !dropping(&stack) {
        out.push_str(&src[pos..]);
    }
    out
}

/// Markers must be known tags, properly nested and closed, never a tag
/// inside itself, and `admin` and `share` never inside one another.
#[cfg(test)]
fn check_markers(src: &str, (open, close): Syntax) -> Result<usize, String> {
    let mut rest = src;
    let mut stack: Vec<String> = Vec::new();
    let mut pairs = 0;
    while let Some(i) = rest.find(open) {
        let after = &rest[i + open.len()..];
        let j = after.find(close).ok_or("unclosed marker")?;
        let tag = after[..j].to_string();
        if tag == "end" {
            stack.pop().ok_or("@end without a start")?;
            pairs += 1;
        } else if !TAGS.contains(&tag.as_str()) {
            return Err(format!("unknown tag @{tag}"));
        } else if stack.contains(&tag) {
            return Err(format!("@{tag} inside itself"));
        } else if (tag == "admin" || tag == "share") && stack.iter().any(|t| t == "admin" || t == "share") {
            return Err(format!("@{tag} inside {stack:?}"));
        } else {
            stack.push(tag);
        }
        rest = &after[j + close.len()..];
    }
    match stack.last() {
        Some(t) => Err(format!("@{t} never ended")),
        None => Ok(pairs),
    }
}

/// Text made safe to put in HTML.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

/// A page for an address that leads nowhere (404), a link that ended (410),
/// too many requests (429) and the like: the route ends in a gap. Only
/// fixed text and pingrail's own messages go in, escaped all the same.
pub fn status_page(code: u16, title: &str, text: &str, back: Option<(&str, &str)>) -> String {
    let back = back
        .map(|(href, label)| format!(r#"<p><a class="nowhere__back trail" href="{}">{}</a></p>"#, esc(href), esc(label)))
        .unwrap_or_default();
    STATUS_HTML
        .replace("{{code}}", &code.to_string())
        .replace("{{title}}", &esc(title))
        .replace("{{text}}", &esc(text))
        .replace("{{back}}", &back)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Windows version resource must match Cargo.toml (it's what the
    /// Apps list and file properties show).
    #[test]
    fn windows_version_resource_matches() {
        let rc = include_str!("../packaging/windows/pingrail.rc");
        let v = env!("CARGO_PKG_VERSION");
        let num = format!("{},0", v.replace('.', ","));
        assert!(rc.contains(&format!("FILEVERSION {num}")), "pingrail.rc FILEVERSION isn't {num}");
        assert!(rc.contains(&format!("PRODUCTVERSION {num}")), "pingrail.rc PRODUCTVERSION isn't {num}");
        assert!(rc.contains(&format!("\"FileVersion\", \"{v}\"")) && rc.contains(&format!("\"ProductVersion\", \"{v}\"")));
    }

    #[test]
    fn cutting_keeps_what_is_wanted() {
        let src = "a\n  <!--@admin-->\n  admin\n  <!--@end-->\n<!--@share-->visitor<!--@add--> adds<!--@end--><!--@end-->\nb\n";
        assert_eq!(cut(src, HTML, &["admin", "add"]), "a\n  admin\n\nb\n");
        assert_eq!(cut(src, HTML, &["share"]), "a\nvisitor\nb\n");
        assert_eq!(cut(src, HTML, &["share", "add"]), "a\nvisitor adds\nb\n");
        // Nested regions are dropped with their parent.
        assert_eq!(cut(src, HTML, &["add"]), "a\n\nb\n");
    }

    #[test]
    fn sources_are_well_marked() {
        assert!(check_markers(INDEX_HTML, HTML).unwrap() > 10);
        assert!(check_markers(APP_JS, JS).unwrap() > 20);
        assert!(check_markers("<!--@admin--><!--@share--><!--@end--><!--@end-->", HTML).is_err());
        assert!(check_markers("<!--@add--><!--@add--><!--@end--><!--@end-->", HTML).is_err());
        assert!(check_markers("<!--@nope--><!--@end-->", HTML).is_err());
        assert!(check_markers("<!--@add-->", HTML).is_err());
    }

    #[test]
    fn every_page_gets_only_its_own_markup_and_code() {
        let p = pages();
        let pages_html: Vec<&str> = std::iter::once(p.admin_html.as_str()).chain(Visitor::ALL.map(|v| p.share_html(v))).collect();
        let pages_js: Vec<&str> = std::iter::once(p.admin_js.as_str()).chain(Visitor::ALL.map(|v| p.share_js(v))).collect();
        for page in pages_html.iter().chain(pages_js.iter()) {
            assert!(!page.contains("<!--@") && !page.contains("/*@"), "a marker was left in a page");
        }
        for v in Visitor::ALL {
            let (html, js) = (p.share_html(v), p.share_js(v));
            for admin_only in [
                "login-form",
                "data-stem",
                "password-dialog",
                "shares-dialog",
                "share-dialog",
                "confirm-dialog",
                "passkeys-dialog",
                "phone-dialog",
                "passkey-signin",
                "t-share",
                "t-bg",
                "data-quick",
                "/app.js",
                "fonts/mona-sans",
            ] {
                assert!(!html.contains(admin_only), "share page {v:?} contains {admin_only}");
            }
            for admin_code in [
                "/api/login", "/api/ping", "/api/password", "/api/shares", "/api/logout", "/api/me", "Login.show", "onShareSave",
                "/api/passkey", "/api/certificate", "/api/qr", "navigator.credentials",
            ] {
                assert!(!js.contains(admin_code), "share script {v:?} contains {admin_code}");
            }
            for add_only in ["target-dialog", "remove-dialog", "t-edit", "t-remove", "t-pause", "add-open", "empty-add"] {
                assert_eq!(html.contains(add_only), v.add, "share page {v:?} and {add_only}");
            }
            for add_code in ["onTargetSave", "openRemove", "gained(", "patchSelected"] {
                assert_eq!(js.contains(add_code), v.add, "share script {v:?} and {add_code}");
            }
            for export_only in ["export-dialog", "export-open"] {
                assert_eq!(html.contains(export_only), v.export, "share page {v:?} and {export_only}");
            }
            for export_code in ["onExport", "${SP}/report"] {
                assert_eq!(js.contains(export_code), v.export, "share script {v:?} and {export_code}");
            }
            assert!(html.contains(&format!(r#"src="{}""#, v.script_path())), "share page {v:?} loads the wrong script");
        }
        for visitor_only in ["share-bar", "closed-msg", "empty-actions", "/share"] {
            assert!(!p.admin_html.contains(visitor_only), "admin page contains {visitor_only}");
        }
        for visitor_code in ["/api/s/", "showVisitor", "applyVisit", "isOwned"] {
            assert!(!p.admin_js.contains(visitor_code), "admin script contains {visitor_code}");
        }
        for admin_has in ["login-form", "target-dialog", "export-dialog", "onTargetSave", "onExport", "Login.show"] {
            assert!(p.admin_html.contains(admin_has) || p.admin_js.contains(admin_has), "admin page lacks {admin_has}");
        }
        assert!(p.admin_html.contains(r#"src="/app.js""#));
        for page in &pages_html {
            assert!(!page.contains("{{"), "a placeholder was left in a page");
            assert!(page.contains(&format!("Version {}", env!("CARGO_PKG_VERSION"))));
            assert!(page.contains(r#"href="https://github.com/ulrich-za/pingrail/issues""#));
        }
    }

    #[test]
    fn scripts_never_write_html() {
        // Every string reaches the page as text: no HTML parsing from script.
        for sink in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"] {
            assert!(!APP_JS.contains(sink), "app.js uses {sink}");
        }
    }

    #[test]
    fn status_pages_escape_everything() {
        let page = status_page(410, "Gone <b>", "It's \"over\" & done", Some(("/?a=<x>", "Back <now>")));
        assert!(page.contains("410"));
        assert!(page.contains("Gone &lt;b&gt;"));
        assert!(page.contains("It&#39;s &quot;over&quot; &amp; done"));
        assert!(page.contains(r#"href="/?a=&lt;x&gt;""#) && page.contains("Back &lt;now&gt;"));
        assert!(!page.contains("{{"), "a placeholder was left in the status page");
        assert!(!status_page(404, "t", "x", None).contains("nowhere__back"));
    }
}

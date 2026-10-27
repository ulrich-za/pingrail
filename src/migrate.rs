//! One-time import from hopwatch, pingrail's earlier name.
//!
//! On first start (no pingrail database yet) pingrail copies hopwatch's
//! database — history, web password, share links — and its settings. The
//! hopwatch folder itself is left untouched.

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::PathBuf;

use crate::config::Paths;

/// The legacy location to import from: `PINGRAIL_IMPORT_FROM` (a folder with
/// hopwatch.db and hopwatch.toml) when set, otherwise `default`.
pub fn source(default: Option<Paths>) -> Option<Paths> {
    match std::env::var_os("PINGRAIL_IMPORT_FROM") {
        Some(dir) if !dir.is_empty() => {
            let dir = PathBuf::from(dir);
            Some(Paths { config_file: dir.join("hopwatch.toml"), data_dir: dir })
        }
        _ => default,
    }
}

/// hopwatch's location matching `paths` (service or local session), if any.
pub fn default_source_for(paths: &Paths) -> Option<Paths> {
    if paths.data_dir == Paths::system().data_dir {
        Some(Paths::legacy_system())
    } else if paths.data_dir == Paths::user().data_dir {
        Paths::legacy_user()
    } else {
        None
    }
}

/// Import if needed, logging rather than failing: a missing or unreadable
/// hopwatch folder must never stop pingrail from starting.
pub fn run(paths: &Paths) {
    let src = source(default_source_for(paths));
    match import_if_needed(paths, src.as_ref()) {
        Ok(Some(msg)) => {
            tracing::info!("{msg}");
            println!("pingrail: {msg}");
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("could not import hopwatch data: {e:#}"),
    }
}

/// Copy hopwatch's database and config into `dest` if `dest` has no database
/// yet. Returns a description of what was imported, or None.
pub fn import_if_needed(dest: &Paths, src: Option<&Paths>) -> Result<Option<String>> {
    let Some(src) = src else { return Ok(None) };
    let src_db = src.data_dir.join("hopwatch.db");
    if dest.db_file().exists() || !src_db.exists() {
        return Ok(None);
    }
    dest.ensure()?;
    // VACUUM INTO writes a consistent copy that includes anything still in
    // hopwatch's write-ahead log.
    let tmp = dest.data_dir.join("pingrail.db.importing");
    let _ = std::fs::remove_file(&tmp);
    {
        let c = Connection::open(&src_db).with_context(|| format!("opening {}", src_db.display()))?;
        c.busy_timeout(std::time::Duration::from_secs(10))?;
        c.execute("VACUUM INTO ?1", [tmp.to_string_lossy().as_ref()])
            .with_context(|| format!("copying {}", src_db.display()))?;
    }
    std::fs::rename(&tmp, dest.db_file()).context("moving the imported database into place")?;

    let mut what = vec!["history", "web password", "share links"];
    if !dest.config_file.exists()
        && let Ok(text) = std::fs::read_to_string(&src.config_file)
    {
        // Rename hopwatch in comments only; values (a public_url, say) stay.
        let converted: Vec<String> = text
            .lines()
            .map(|l| if l.trim_start().starts_with('#') { l.replace("hopwatch", "pingrail") } else { l.to_string() })
            .collect();
        if let Some(dir) = dest.config_file.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        std::fs::write(&dest.config_file, converted.join("\n") + "\n").context("writing pingrail.toml")?;
        what.push("settings");
    }
    let list = match what.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => what.join(""),
    };
    Ok(Some(format!("imported {list} from hopwatch ({})", src.data_dir.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_database_and_settings_once() {
        let base = std::env::temp_dir().join(format!("pingrail-migrate-{}", crate::config::random_hex(4)));
        let old = Paths { config_file: base.join("old/hopwatch.toml"), data_dir: base.join("old") };
        let new = Paths::in_dir(&base.join("new"));
        std::fs::create_dir_all(&old.data_dir).unwrap();
        {
            let c = Connection::open(old.data_dir.join("hopwatch.db")).unwrap();
            c.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES (42);").unwrap();
            // Leave the row in the WAL: VACUUM INTO must still see it.
            std::fs::write(&old.config_file, "# hopwatch settings\n[share]\npublic_url = \"https://hopwatch.example.com\"\n").unwrap();
            let msg = import_if_needed(&new, Some(&old)).unwrap().unwrap();
            assert!(msg.contains("settings"), "{msg}");
        }
        let c = Connection::open(new.db_file()).unwrap();
        let x: i64 = c.query_row("SELECT x FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(x, 42);
        let cfg = std::fs::read_to_string(&new.config_file).unwrap();
        assert!(cfg.starts_with("# pingrail settings"));
        assert!(cfg.contains("https://hopwatch.example.com"), "values are not renamed");
        assert!(import_if_needed(&new, Some(&old)).unwrap().is_none(), "only once");
        let _ = std::fs::remove_dir_all(&base);
    }
}

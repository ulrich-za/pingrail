//! msisort: check, and with --fix repair, an MSI whose table rows aren't
//! stored in primary-key order. Windows Installer refuses to load such a
//! table (errors 2211/2229); msitools' wixl can write them out of order (it
//! does for pingrail's Upgrade table).
//!
//!     msisort [--fix] FILE.msi...
//!
//! Exits 1 when a table is out of order (after fixing, it re-checks).
//!
//! An MSI is a compound file. Each table is a stream of fixed-width columns,
//! stored column after column; strings are stored as indexes into the
//! string pool. Windows keeps rows sorted by their primary-key columns'
//! stored values (string indexes and offset integers), so that's the order
//! this restores. Rows are only reordered, never changed, so every stream
//! keeps its size and is rewritten in place.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Characters of MSI's stream-name encoding.
const CHARS: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

/// Decode an MSI stream name (pairs of name characters packed into one
/// UTF-16 unit; '!' marks a table).
fn decode(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        let c = ch as u32;
        if (0x3800..0x4800).contains(&c) {
            let c = c - 0x3800;
            out.push(CHARS[(c & 0x3f) as usize] as char);
            out.push(CHARS[((c >> 6) & 0x3f) as usize] as char);
        } else if (0x4800..0x4840).contains(&c) {
            out.push(CHARS[(c - 0x4800) as usize] as char);
        } else if c == 0x4840 {
            out.push('!');
        } else {
            out.push(ch);
        }
    }
    out
}

type Msi = cfb::CompoundFile<std::fs::File>;

fn read_stream(msi: &mut Msi, path: &Path) -> std::io::Result<Vec<u8>> {
    let mut s = msi.open_stream(path)?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    Ok(buf)
}

struct Column {
    width: usize,
    key: bool,
}

/// Returns how many tables were out of order.
fn process(path: &Path, fix: bool) -> Result<usize, String> {
    let file = std::fs::OpenOptions::new().read(true).write(fix).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut msi = cfb::CompoundFile::open(file).map_err(|e| format!("{}: not an MSI ({e})", path.display()))?;
    let streams: BTreeMap<String, PathBuf> = msi
        .walk()
        .filter(|e| e.is_stream())
        .map(|e| (decode(e.name()), e.path().to_path_buf()))
        .collect();
    let get = |name: &str| streams.get(name).cloned().ok_or_else(|| format!("{}: no {name} stream", path.display()));

    // String pool: header (code page, flags), then (length, refcount) pairs.
    let pool = read_stream(&mut msi, &get("!_StringPool")?).map_err(|e| e.to_string())?;
    if pool.len() < 4 {
        return Err("string pool too short".into());
    }
    let flags = u16::from_le_bytes([pool[2], pool[3]]);
    let sw = if flags & 0x8000 != 0 { 3 } else { 2 };

    // Column definitions: _Columns(Table, Number, Name, Type), column-wise.
    let cols = read_stream(&mut msi, &get("!_Columns")?).map_err(|e| e.to_string())?;
    let n = cols.len() / (sw + 2 + sw + 2);
    let uint = |b: &[u8]| b.iter().rev().fold(0u32, |acc, x| (acc << 8) | *x as u32);
    let mut defs: Vec<(u32, u16, u16)> = Vec::new(); // (table string id, number, type)
    for j in 0..n {
        let table = uint(&cols[j * sw..j * sw + sw]);
        let numb = &cols[n * sw + j * 2..n * sw + j * 2 + 2];
        let typb = &cols[n * (sw + 2 + sw) + j * 2..n * (sw + 2 + sw) + j * 2 + 2];
        let number = u16::from_le_bytes([numb[0], numb[1]]).wrapping_sub(0x8000);
        let ty = u16::from_le_bytes([typb[0], typb[1]]).wrapping_sub(0x8000);
        defs.push((table, number, ty));
    }

    // Table names from the string pool.
    let data = read_stream(&mut msi, &get("!_StringData")?).map_err(|e| e.to_string())?;
    let mut strings = vec![String::new()];
    let (mut off, mut i) = (0usize, 4usize);
    while i + 4 <= pool.len() {
        let mut len = u16::from_le_bytes([pool[i], pool[i + 1]]) as usize;
        let refs = u16::from_le_bytes([pool[i + 2], pool[i + 3]]);
        i += 4;
        if len == 0 && refs != 0 && i + 4 <= pool.len() {
            // Long string: the next entry holds the low 16 bits.
            let lo = u16::from_le_bytes([pool[i], pool[i + 1]]) as usize;
            len = ((refs as usize) << 16) | lo;
            i += 4;
        }
        let end = (off + len).min(data.len());
        strings.push(String::from_utf8_lossy(&data[off..end]).into_owned());
        off = end;
    }

    let mut tables: BTreeMap<String, Vec<(u16, u16)>> = BTreeMap::new();
    for (t, number, ty) in defs {
        let name = strings.get(t as usize).cloned().unwrap_or_default();
        tables.entry(name).or_default().push((number, ty));
    }

    let mut bad = 0;
    for (name, mut defs) in tables {
        defs.sort();
        let Some(stream) = streams.get(&format!("!{name}")) else { continue }; // empty table
        let columns: Vec<Column> = defs
            .iter()
            .map(|(_, ty)| Column {
                width: if ty & 0x0800 != 0 {
                    sw
                } else if ty & 0xff == 4 {
                    4
                } else {
                    2
                },
                key: ty & 0x2000 != 0,
            })
            .collect();
        let row_len: usize = columns.iter().map(|c| c.width).sum();
        let blob = read_stream(&mut msi, stream).map_err(|e| e.to_string())?;
        if row_len == 0 || blob.len() % row_len != 0 {
            return Err(format!("{name}: stream size doesn't match its columns"));
        }
        let rows = blob.len() / row_len;
        // Split into columns of cells.
        let mut cells: Vec<Vec<&[u8]>> = Vec::new();
        let mut pos = 0;
        for c in &columns {
            cells.push((0..rows).map(|r| &blob[pos + r * c.width..pos + (r + 1) * c.width]).collect());
            pos += rows * c.width;
        }
        let key = |r: usize| -> Vec<u32> {
            columns.iter().enumerate().filter(|(_, c)| c.key).map(|(k, _)| uint(cells[k][r])).collect()
        };
        let mut order: Vec<usize> = (0..rows).collect();
        order.sort_by_key(|&r| key(r));
        let sorted = order.iter().copied().eq(0..rows);
        let mut keys: Vec<Vec<u32>> = (0..rows).map(key).collect();
        keys.sort();
        keys.dedup();
        let duplicates = keys.len() != rows;
        let status = match (sorted, duplicates) {
            (true, false) => "ok",
            (false, false) => "OUT OF ORDER",
            (_, true) => "DUPLICATE KEYS",
        };
        println!("  {name:24} {rows:4} rows  {status}");
        if status != "ok" {
            bad += 1;
        }
        if fix && !sorted && !duplicates {
            let mut new = Vec::with_capacity(blob.len());
            for col in &cells {
                for &r in &order {
                    new.extend_from_slice(col[r]);
                }
            }
            let mut s = msi.open_stream(stream).map_err(|e| e.to_string())?;
            s.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            s.write_all(&new).map_err(|e| e.to_string())?;
            s.flush().map_err(|e| e.to_string())?;
        }
    }
    if fix {
        msi.flush().map_err(|e| e.to_string())?;
    }
    Ok(bad)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let fix = args.iter().any(|a| a == "--fix");
    let files: Vec<&String> = args.iter().filter(|a| *a != "--fix").collect();
    if files.is_empty() {
        eprintln!("usage: msisort [--fix] FILE.msi...");
        return ExitCode::from(2);
    }
    let mut failed = false;
    for f in files {
        println!("{f}:");
        let path = Path::new(f);
        let result = process(path, fix).and_then(|bad| if fix && bad > 0 { process(path, false) } else { Ok(bad) });
        match result {
            Ok(0) => {}
            Ok(_) => failed = true,
            Err(e) => {
                eprintln!("error: {e}");
                failed = true;
            }
        }
    }
    if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

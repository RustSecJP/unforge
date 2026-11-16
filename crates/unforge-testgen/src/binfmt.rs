//! Matching files against a snapshot of `/proc/sys/fs/binfmt_misc`.
//!
//! The snapshot is the text `run_oracle.sh` dumps: for each entry a line
//! `### <name>` followed by the entry file's contents (`enabled`,
//! `interpreter <path>`, `flags: ...`, `offset <n>`, `magic <hex>`,
//! `mask <hex>`). Matching follows `fs/binfmt_misc.c:check_file` (Linux
//! v7.0.12): an enabled magic entry matches when, for every byte j,
//! `(buf[offset + j] ^ magic[j]) & mask[j] == 0`. Extension entries
//! (`extension .foo`) never match an ELF test file and are ignored.

pub struct Entry {
    pub name: String,
    pub enabled: bool,
    pub offset: usize,
    pub magic: Vec<u8>,
    pub mask: Vec<u8>,
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}

pub fn parse(text: &str) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("### ") {
            out.push(Entry {
                name: name.to_string(),
                enabled: false,
                offset: 0,
                magic: Vec::new(),
                mask: Vec::new(),
            });
            continue;
        }
        let Some(e) = out.last_mut() else { continue };
        if line == "enabled" {
            e.enabled = true;
        } else if let Some(v) = line.strip_prefix("offset ") {
            e.offset = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("magic ") {
            e.magic = hex(v.trim());
        } else if let Some(v) = line.strip_prefix("mask ") {
            e.mask = hex(v.trim());
        }
    }
    // "status" and "register" are control files, not entries.
    out.retain(|e| !e.magic.is_empty());
    out
}

pub fn matching(entries: &[Entry], file: &[u8]) -> Vec<String> {
    entries
        .iter()
        .filter(|e| e.enabled)
        .filter(|e| {
            e.magic.iter().enumerate().all(|(j, &m)| {
                let mask = e.mask.get(j).copied().unwrap_or(0xff);
                file.get(e.offset + j).is_some_and(|&b| (b ^ m) & mask == 0)
            })
        })
        .map(|e| e.name.clone())
        .collect()
}

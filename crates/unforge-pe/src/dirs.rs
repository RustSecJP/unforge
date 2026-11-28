//! The data directories: imports, exports, base relocations, the x64
//! exception table, TLS and debug entries.
//!
//! Every reader takes a [`Sink`]; the public accessors pass a quiet one and
//! [`audit`] a recording one, so the walk is written once.

use crate::diag::{DiagnosticKind as K, Severity, Sink};
use crate::read::{cstr, u8_at, u16_at, u32_at, usize_of, word_at};
use crate::{
    MACHINE_AMD64, MAX_DEBUG_ENTRIES, MAX_EXPORTS, MAX_IMPORT_DLLS, MAX_IMPORTS, MAX_NAME_LEN,
    MAX_RUNTIME_FUNCTIONS, MAX_TLS_CALLBACKS, PeFile, PeKind, dir,
};

/// One imported DLL (`IMAGE_IMPORT_DESCRIPTOR`) and what is imported from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDll<'data> {
    /// The DLL name as written (`KERNEL32.dll`), at most
    /// [`MAX_NAME_LEN`] bytes.
    pub name: &'data [u8],
    /// RVA of the import lookup table (`OriginalFirstThunk`), 0 if none.
    pub lookup_rva: u32,
    /// RVA of the import address table (`FirstThunk`).
    pub iat_rva: u32,
    pub time_date_stamp: u32,
    pub entries: Vec<Import<'data>>,
}

/// One imported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import<'data> {
    /// RVA of its IAT slot: the loader writes the function's address there,
    /// and code calls through it (`call [rip+slot]`).
    pub slot_rva: u32,
    pub kind: ImportKind<'data>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportKind<'data> {
    /// By name, with the hint (an index into the DLL's export name table).
    Name { hint: u16, name: &'data [u8] },
    /// By ordinal.
    Ordinal(u16),
    /// The thunk points to no readable hint/name entry (the raw thunk).
    Unreadable(u64),
}

impl ImportDll<'_> {
    /// `dll!name` (or `dll!#ordinal`) for each entry, readable for display.
    pub fn display_names(&self) -> impl Iterator<Item = (u32, String)> + '_ {
        let dll = String::from_utf8_lossy(self.name);
        self.entries.iter().map(move |e| {
            let what = match &e.kind {
                ImportKind::Name { name, .. } => String::from_utf8_lossy(name).into_owned(),
                ImportKind::Ordinal(o) => format!("#{o}"),
                ImportKind::Unreadable(t) => format!("?{t:x}"),
            };
            (e.slot_rva, format!("{dll}!{what}"))
        })
    }
}

/// The export directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exports<'data> {
    /// The DLL's own name, if readable.
    pub dll_name: Option<&'data [u8]>,
    /// `Base`: the ordinal of the first function.
    pub ordinal_base: u32,
    /// Exports with a non-zero address, by ordinal.
    pub entries: Vec<Export<'data>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export<'data> {
    pub ordinal: u32,
    /// RVA of the code or data (for a forwarder, of the forwarder string).
    pub rva: u32,
    /// The first name pointing to this function.
    pub name: Option<&'data [u8]>,
    /// `OTHERDLL.Function` when the RVA points inside the export directory.
    pub forwarder: Option<&'data [u8]>,
}

/// One base relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    /// RVA of the patched word.
    pub rva: u64,
    /// `IMAGE_REL_BASED_*`: 3 `HIGHLOW` (4 bytes), 10 `DIR64` (8 bytes), ...
    pub kind: u8,
}

/// `IMAGE_REL_BASED_HIGHLOW`
pub const REL_BASED_HIGHLOW: u8 = 3;
/// `IMAGE_REL_BASED_DIR64`
pub const REL_BASED_DIR64: u8 = 10;

/// An x64 `RUNTIME_FUNCTION`: one function (or a part of one) with unwind
/// data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin: u32,
    /// Exclusive.
    pub end: u32,
    pub unwind_info: u32,
    /// The unwind info is chained (`UNW_FLAG_CHAININFO`) or the entry
    /// points to another entry (bit 0 of `UnwindData`): this range is a
    /// part of a function that starts elsewhere, not a function start.
    pub chained: bool,
}

/// The TLS directory, with its callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    /// Callback addresses (VAs), up to the terminating 0.
    pub callbacks: Vec<u64>,
}

/// One debug directory entry (`IMAGE_DEBUG_DIRECTORY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugEntry {
    /// `IMAGE_DEBUG_TYPE_*`: 2 CodeView, 13 POGO, 16 repro, 20 ex-dllcharacteristics, ...
    pub kind: u32,
    pub time_date_stamp: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

/// A CodeView record: where the PDB was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeView<'data> {
    /// `RSDS` (PDB 7) or `NB10` (PDB 2).
    pub signature: [u8; 4],
    /// The PDB GUID (`RSDS`); for `NB10`, the 4-byte signature then zeros.
    pub guid: [u8; 16],
    pub age: u32,
    /// The PDB path the linker wrote (often the build directory).
    pub path: &'data [u8],
}

/// `IMAGE_DEBUG_TYPE_CODEVIEW`
pub const DEBUG_TYPE_CODEVIEW: u32 = 2;

impl<'data> PeFile<'data> {
    /// The imported DLLs, in table order.
    pub fn imports(&self) -> Vec<ImportDll<'data>> {
        imports(self, &mut Sink::quiet())
    }

    /// Every IAT slot (RVA) with `dll!name`, for naming indirect calls.
    pub fn iat_names(&self) -> Vec<(u32, String)> {
        self.imports()
            .iter()
            .flat_map(|d| d.display_names().collect::<Vec<_>>())
            .collect()
    }

    /// The export directory, if any.
    pub fn exports(&self) -> Option<Exports<'data>> {
        exports(self, &mut Sink::quiet())
    }

    /// The base relocations, in table order.
    pub fn relocations(&self) -> Relocations<'data> {
        Relocations::new(self)
    }

    /// The `RUNTIME_FUNCTION` entries of the exception directory (x64
    /// only; empty for other machines), in table order.
    pub fn runtime_functions(&self) -> Vec<RuntimeFunction> {
        runtime_functions(self, &mut Sink::quiet())
    }

    /// The TLS directory and its callbacks.
    pub fn tls(&self) -> Option<Tls> {
        tls(self, &mut Sink::quiet())
    }

    /// The debug directory entries.
    pub fn debug_entries(&self) -> Vec<DebugEntry> {
        debug_entries(self, &mut Sink::quiet())
    }

    /// The first readable CodeView record (the PDB path).
    pub fn codeview(&self) -> Option<CodeView<'data>> {
        codeview(self, &mut Sink::quiet())
    }
}

/// The bytes of directory `index` (clipped to its size and to what the
/// file backs), with its RVA.
fn dir_bytes<'data>(pe: &PeFile<'data>, index: usize) -> Option<(u32, &'data [u8])> {
    let d = pe.directory(index)?;
    let b = pe.slice_at_rva(u64::from(d.rva), u64::from(d.size))?;
    Some((d.rva, b))
}

/// A NUL-terminated name at `rva`.
fn name_at<'data>(pe: &PeFile<'data>, rva: u64) -> Option<(&'data [u8], bool)> {
    let b = pe.bytes_at_rva(rva)?;
    Some(cstr(b, MAX_NAME_LEN))
}

fn imports<'data>(pe: &PeFile<'data>, sink: &mut Sink) -> Vec<ImportDll<'data>> {
    let mut out = Vec::new();
    let Some(d) = pe.directory(dir::IMPORT) else {
        return out;
    };
    // The loader reads descriptors until an all-zero one and ignores the
    // directory size, so do the same (bounded by the mapped bytes).
    let Some(table) = pe.bytes_at_rva(u64::from(d.rva)) else {
        return out;
    };
    let ptr = pe.kind().pointer_size();
    let ord_flag = match pe.kind() {
        PeKind::Pe32 => 1u64 << 31,
        PeKind::Pe32Plus => 1u64 << 63,
    };
    let mut total = 0usize;
    let mut terminated = false;
    for i in 0..MAX_IMPORT_DLLS {
        let at = i * 20;
        let Some(desc) = table.get(at..at + 20) else {
            break;
        };
        if desc.iter().all(|&b| b == 0) {
            terminated = true;
            break;
        }
        let lookup = u32_at(desc, 0).unwrap_or(0);
        let time_date_stamp = u32_at(desc, 4).unwrap_or(0);
        let name_rva = u32_at(desc, 12).unwrap_or(0);
        let iat = u32_at(desc, 16).unwrap_or(0);
        let name = match name_at(pe, u64::from(name_rva)) {
            Some((n, cut)) => {
                if cut {
                    sink.push(Severity::Warning, K::ImportNameBad, None, || {
                        format!("import {i}: the DLL name at RVA {name_rva:#x} is not terminated")
                    });
                }
                n
            }
            None => {
                sink.push(Severity::Warning, K::ImportNameBad, None, || {
                    format!("import {i}: the DLL name RVA {name_rva:#x} is not backed by the file")
                });
                &[][..]
            }
        };
        let thunks_rva = if lookup != 0 { lookup } else { iat };
        let mut entries = Vec::new();
        match pe.bytes_at_rva(u64::from(thunks_rva)) {
            None => sink.push(Severity::Warning, K::ImportsTruncated, None, || {
                format!(
                    "import {i} ({}): the thunk table at RVA {thunks_rva:#x} is not backed by the file",
                    String::from_utf8_lossy(name)
                )
            }),
            Some(thunks) => {
                let mut j = 0usize;
                loop {
                    if total >= MAX_IMPORTS {
                        sink.push(Severity::Info, K::OutputCapped, None, || {
                            format!("more than {MAX_IMPORTS} imports; the rest are not read")
                        });
                        break;
                    }
                    let Some(t) = word_at(thunks, j * ptr, ptr) else {
                        sink.push(Severity::Warning, K::ImportsTruncated, None, || {
                            format!(
                                "import {i}: the thunk table at RVA {thunks_rva:#x} runs past its section without a terminator"
                            )
                        });
                        break;
                    };
                    if t == 0 {
                        break;
                    }
                    let slot = u64::from(iat).saturating_add((j * ptr) as u64);
                    let kind = if t & ord_flag != 0 {
                        ImportKind::Ordinal((t & 0xffff) as u16)
                    } else {
                        let hn = t & 0x7fff_ffff;
                        match pe.bytes_at_rva(hn) {
                            Some(b) if b.len() >= 2 => {
                                let hint = u16_at(b, 0).unwrap_or(0);
                                let (n, cut) = cstr(b.get(2..).unwrap_or_default(), MAX_NAME_LEN);
                                if cut || n.is_empty() {
                                    sink.push(Severity::Warning, K::ImportNameBad, None, || {
                                        format!("import name at RVA {hn:#x} is empty or not terminated")
                                    });
                                }
                                ImportKind::Name { hint, name: n }
                            }
                            _ => {
                                sink.push(Severity::Warning, K::ImportNameBad, None, || {
                                    format!("import hint/name RVA {hn:#x} is not backed by the file")
                                });
                                ImportKind::Unreadable(t)
                            }
                        }
                    };
                    entries.push(Import {
                        slot_rva: u32::try_from(slot).unwrap_or(u32::MAX),
                        kind,
                    });
                    total += 1;
                    j += 1;
                }
            }
        }
        out.push(ImportDll {
            name,
            lookup_rva: lookup,
            iat_rva: iat,
            time_date_stamp,
            entries,
        });
    }
    if !terminated && out.len() < MAX_IMPORT_DLLS {
        sink.push(Severity::Warning, K::ImportsTruncated, None, || {
            format!(
                "the import descriptors at RVA {:#x} run past their section without a terminator",
                d.rva
            )
        });
    }
    out
}

fn exports<'data>(pe: &PeFile<'data>, sink: &mut Sink) -> Option<Exports<'data>> {
    let d = pe.directory(dir::EXPORT)?;
    let Some(h) = pe
        .slice_at_rva(u64::from(d.rva), 40)
        .filter(|h| h.len() == 40)
    else {
        sink.push(Severity::Warning, K::ExportsTruncated, None, || {
            format!(
                "the export directory at RVA {:#x} is not backed by 40 file bytes",
                d.rva
            )
        });
        return None;
    };
    let name_rva = u32_at(h, 12).unwrap_or(0);
    let base = u32_at(h, 16).unwrap_or(0);
    let nfun = usize_of(u64::from(u32_at(h, 20).unwrap_or(0)));
    let nnames = usize_of(u64::from(u32_at(h, 24).unwrap_or(0)));
    let funcs_rva = u32_at(h, 28).unwrap_or(0);
    let names_rva = u32_at(h, 32).unwrap_or(0);
    let ords_rva = u32_at(h, 36).unwrap_or(0);
    let dll_name = name_at(pe, u64::from(name_rva)).map(|(n, _)| n);
    if nfun > MAX_EXPORTS || nnames > MAX_EXPORTS {
        sink.push(Severity::Info, K::OutputCapped, None, || {
            format!("{nfun} exports / {nnames} names; at most {MAX_EXPORTS} are read")
        });
    }
    let funcs = pe.bytes_at_rva(u64::from(funcs_rva)).unwrap_or_default();
    let avail = (funcs.len() / 4).min(nfun).min(MAX_EXPORTS);
    if avail < nfun.min(MAX_EXPORTS) {
        sink.push(Severity::Warning, K::ExportsTruncated, None, || {
            format!(
                "the export address table declares {nfun} entries, {avail} are backed by the file"
            )
        });
    }
    let mut names: Vec<Option<&'data [u8]>> = vec![None; avail];
    let name_ptrs = pe.bytes_at_rva(u64::from(names_rva)).unwrap_or_default();
    let ords = pe.bytes_at_rva(u64::from(ords_rva)).unwrap_or_default();
    let nn = nnames
        .min(MAX_EXPORTS)
        .min(name_ptrs.len() / 4)
        .min(ords.len() / 2);
    if nn < nnames.min(MAX_EXPORTS) {
        sink.push(Severity::Warning, K::ExportsTruncated, None, || {
            format!("the export name tables declare {nnames} names, {nn} are backed by the file")
        });
    }
    for k in 0..nn {
        let (Some(np), Some(ord)) = (u32_at(name_ptrs, k * 4), u16_at(ords, k * 2)) else {
            break;
        };
        let Some(slot) = names.get_mut(usize::from(ord)) else {
            sink.push(Severity::Warning, K::ExportNameBad, None, || {
                format!("export name {k} has ordinal index {ord}, past the {avail} functions")
            });
            continue;
        };
        match name_at(pe, u64::from(np)) {
            Some((n, false)) if !n.is_empty() => {
                if slot.is_none() {
                    *slot = Some(n);
                }
            }
            _ => sink.push(Severity::Warning, K::ExportNameBad, None, || {
                format!("export name {k} at RVA {np:#x} is unreadable")
            }),
        }
    }
    let dir_start = u64::from(d.rva);
    let dir_end = dir_start.saturating_add(u64::from(d.size));
    let mut entries = Vec::new();
    for (i, name) in names.into_iter().enumerate() {
        let Some(rva) = u32_at(funcs, i * 4) else {
            break;
        };
        if rva == 0 {
            continue;
        }
        let r = u64::from(rva);
        let forwarder = (r >= dir_start && r < dir_end)
            .then(|| name_at(pe, r).map(|(n, _)| n))
            .flatten();
        entries.push(Export {
            ordinal: base.wrapping_add(i as u32),
            rva,
            name,
            forwarder,
        });
    }
    Some(Exports {
        dll_name,
        ordinal_base: base,
        entries,
    })
}

/// Iterator over the base relocations ([`PeFile::relocations`]). It reads
/// the blocks lazily and allocates nothing.
#[derive(Debug, Clone)]
pub struct Relocations<'data> {
    bytes: &'data [u8],
    /// Offset of the current block.
    block: usize,
    page: u64,
    /// Entries of the current block: [next, end) offsets.
    next: usize,
    end: usize,
    /// A block header was malformed (the rest is not read).
    pub truncated: bool,
}

impl<'data> Relocations<'data> {
    fn new(pe: &PeFile<'data>) -> Self {
        let bytes = dir_bytes(pe, dir::BASERELOC).map_or(&[][..], |(_, b)| b);
        Relocations {
            bytes,
            block: 0,
            page: 0,
            next: 0,
            end: 0,
            truncated: false,
        }
    }
}

impl Iterator for Relocations<'_> {
    type Item = Relocation;

    fn next(&mut self) -> Option<Relocation> {
        loop {
            if self.next + 2 <= self.end {
                let e = u16_at(self.bytes, self.next)?;
                self.next += 2;
                let kind = (e >> 12) as u8;
                if kind == 0 {
                    continue; // IMAGE_REL_BASED_ABSOLUTE: padding
                }
                return Some(Relocation {
                    rva: self.page + u64::from(e & 0xfff),
                    kind,
                });
            }
            // Next block.
            if self.block >= self.bytes.len() {
                return None;
            }
            let (Some(page), Some(size)) = (
                u32_at(self.bytes, self.block),
                u32_at(self.bytes, self.block + 4),
            ) else {
                self.truncated = true;
                return None;
            };
            let size = usize_of(u64::from(size));
            if size < 8 {
                // A zero block ends the table in practice (padding).
                self.truncated = size != 0 || page != 0;
                return None;
            }
            let end = self.block.saturating_add(size);
            if end > self.bytes.len() {
                self.truncated = true;
            }
            self.page = u64::from(page);
            self.next = self.block + 8;
            self.end = end.min(self.bytes.len());
            self.block = end;
        }
    }
}

fn runtime_functions(pe: &PeFile<'_>, sink: &mut Sink) -> Vec<RuntimeFunction> {
    let mut out = Vec::new();
    if pe.machine() != MACHINE_AMD64 {
        return out;
    }
    let Some(d) = pe.directory(dir::EXCEPTION) else {
        return out;
    };
    let b = pe
        .slice_at_rva(u64::from(d.rva), u64::from(d.size))
        .unwrap_or_default();
    let declared = usize_of(u64::from(d.size)) / 12;
    let n = (b.len() / 12).min(MAX_RUNTIME_FUNCTIONS);
    if n < declared.min(MAX_RUNTIME_FUNCTIONS) {
        sink.push(Severity::Warning, K::ExceptionTableTruncated, None, || {
            format!(
                "the exception directory declares {declared} entries, {n} are backed by the file"
            )
        });
    }
    if declared > MAX_RUNTIME_FUNCTIONS {
        sink.push(Severity::Info, K::OutputCapped, None, || {
            format!("{declared} RUNTIME_FUNCTION entries; at most {MAX_RUNTIME_FUNCTIONS} are read")
        });
    }
    out.reserve(n);
    let mut prev_begin = 0u32;
    for i in 0..n {
        let (Some(begin), Some(end), Some(unwind)) = (
            u32_at(b, i * 12),
            u32_at(b, i * 12 + 4),
            u32_at(b, i * 12 + 8),
        ) else {
            break;
        };
        if begin == 0 && end == 0 && unwind == 0 {
            continue; // padding at the end of .pdata
        }
        if end <= begin || !pe.is_executable_rva(u64::from(begin)) {
            sink.push(Severity::Warning, K::ExceptionEntryBad, None, || {
                format!(
                    "RUNTIME_FUNCTION {i} ({begin:#x}..{end:#x}) is empty or not in executable memory"
                )
            });
            if end <= begin {
                continue;
            }
        }
        if begin < prev_begin {
            sink.push(Severity::Warning, K::ExceptionEntryBad, None, || {
                format!("RUNTIME_FUNCTION {i} at {begin:#x} is out of order (the loader binary-searches this table)")
            });
        }
        prev_begin = begin;
        let chained = unwind & 1 != 0
            || pe
                .bytes_at_rva(u64::from(unwind))
                .and_then(|u| u8_at(u, 0))
                .is_some_and(|v| (v >> 3) & 0x4 != 0);
        out.push(RuntimeFunction {
            begin,
            end,
            unwind_info: unwind,
            chained,
        });
    }
    out
}

fn tls(pe: &PeFile<'_>, sink: &mut Sink) -> Option<Tls> {
    let d = pe.directory(dir::TLS)?;
    let p = pe.kind().pointer_size();
    let need = 4 * p + 8;
    let Some(h) = pe
        .slice_at_rva(u64::from(d.rva), need as u64)
        .filter(|h| h.len() == need)
    else {
        sink.push(Severity::Warning, K::TlsTruncated, None, || {
            format!(
                "the TLS directory at RVA {:#x} is not backed by {need} file bytes",
                d.rva
            )
        });
        return None;
    };
    let w = |i: usize| word_at(h, i * p, p).unwrap_or(0);
    let mut t = Tls {
        start_address_of_raw_data: w(0),
        end_address_of_raw_data: w(1),
        address_of_index: w(2),
        address_of_callbacks: w(3),
        size_of_zero_fill: u32_at(h, 4 * p).unwrap_or(0),
        characteristics: u32_at(h, 4 * p + 4).unwrap_or(0),
        callbacks: Vec::new(),
    };
    if t.address_of_callbacks != 0 {
        match pe.bytes_at_va(t.address_of_callbacks) {
            None => sink.push(Severity::Warning, K::TlsTruncated, None, || {
                format!(
                    "the TLS callback array at {:#x} is not backed by the file",
                    t.address_of_callbacks
                )
            }),
            Some(arr) => {
                for i in 0..MAX_TLS_CALLBACKS {
                    let Some(cb) = word_at(arr, i * p, p) else {
                        sink.push(Severity::Warning, K::TlsTruncated, None, || {
                            "the TLS callback array has no terminator".to_owned()
                        });
                        break;
                    };
                    if cb == 0 {
                        break;
                    }
                    let inside = pe.va_to_rva(cb).is_some_and(|r| pe.is_executable_rva(r));
                    if !inside {
                        sink.push(Severity::Warning, K::TlsCallbackOutside, None, || {
                            format!("TLS callback {i} at {cb:#x} is not in executable memory of the image")
                        });
                    }
                    t.callbacks.push(cb);
                }
            }
        }
    }
    Some(t)
}

fn debug_entries(pe: &PeFile<'_>, sink: &mut Sink) -> Vec<DebugEntry> {
    let mut out = Vec::new();
    let Some((rva, b)) = dir_bytes(pe, dir::DEBUG) else {
        return out;
    };
    let declared = pe.directory(dir::DEBUG).map_or(0, |d| d.size as usize / 28);
    let n = (b.len() / 28).min(MAX_DEBUG_ENTRIES);
    if n < declared.min(MAX_DEBUG_ENTRIES) {
        sink.push(Severity::Warning, K::DebugDirectoryTruncated, None, || {
            format!("the debug directory at RVA {rva:#x} declares {declared} entries, {n} are backed by the file")
        });
    }
    for i in 0..n {
        let o = i * 28;
        out.push(DebugEntry {
            time_date_stamp: u32_at(b, o + 4).unwrap_or(0),
            kind: u32_at(b, o + 12).unwrap_or(0),
            size_of_data: u32_at(b, o + 16).unwrap_or(0),
            address_of_raw_data: u32_at(b, o + 20).unwrap_or(0),
            pointer_to_raw_data: u32_at(b, o + 24).unwrap_or(0),
        });
    }
    out
}

fn codeview<'data>(pe: &PeFile<'data>, sink: &mut Sink) -> Option<CodeView<'data>> {
    for e in debug_entries(pe, &mut Sink::quiet()) {
        if e.kind != DEBUG_TYPE_CODEVIEW {
            continue;
        }
        let size = usize_of(u64::from(e.size_of_data));
        let by_offset = usize_of(u64::from(e.pointer_to_raw_data));
        let b = pe
            .data()
            .get(by_offset..by_offset.saturating_add(size).min(pe.data().len()))
            .filter(|b| e.pointer_to_raw_data != 0 && b.len() >= 4)
            .or_else(|| pe.slice_at_rva(u64::from(e.address_of_raw_data), size as u64));
        let Some(b) = b.filter(|b| b.len() >= 4) else {
            sink.push(Severity::Warning, K::CodeViewBad, None, || {
                "a CodeView debug entry points outside the file".to_owned()
            });
            continue;
        };
        let mut signature = [0u8; 4];
        signature.copy_from_slice(b.get(..4)?);
        let (guid, age, path_at) = match &signature {
            b"RSDS" => {
                let mut g = [0u8; 16];
                if let Some(s) = b.get(4..20) {
                    g.copy_from_slice(s);
                }
                (g, u32_at(b, 20), 24)
            }
            b"NB10" => {
                let mut g = [0u8; 16];
                if let Some(s) = b.get(8..12) {
                    g.get_mut(..4)?.copy_from_slice(s);
                }
                (g, u32_at(b, 12), 16)
            }
            _ => {
                sink.push(Severity::Info, K::CodeViewBad, None, || {
                    format!("CodeView record with unknown signature {signature:02x?}")
                });
                continue;
            }
        };
        let Some(age) = age else {
            sink.push(Severity::Warning, K::CodeViewBad, None, || {
                "the CodeView record is cut short".to_owned()
            });
            continue;
        };
        let (path, cut) = cstr(b.get(path_at..).unwrap_or_default(), MAX_NAME_LEN);
        if cut {
            sink.push(Severity::Warning, K::CodeViewBad, None, || {
                "the CodeView PDB path is not terminated".to_owned()
            });
        }
        return Some(CodeView {
            signature,
            guid,
            age,
            path,
        });
    }
    None
}

/// Walks every directory with a recording sink.
pub(crate) fn audit(pe: &PeFile<'_>, sink: &mut Sink) {
    let _ = imports(pe, sink);
    let _ = exports(pe, sink);
    let mut relocs = pe.relocations();
    let mut unknown = 0usize;
    for r in relocs.by_ref() {
        if !matches!(r.kind, REL_BASED_HIGHLOW | REL_BASED_DIR64) {
            unknown += 1;
            if unknown <= 4 {
                sink.push(Severity::Info, K::RelocationUnknownType, None, || {
                    format!("base relocation of type {} at RVA {:#x}", r.kind, r.rva)
                });
            }
        }
    }
    if relocs.truncated {
        sink.push(Severity::Warning, K::RelocationsTruncated, None, || {
            "a base relocation block is malformed or runs past the directory".to_owned()
        });
    }
    let _ = runtime_functions(pe, sink);
    let _ = tls(pe, sink);
    let _ = debug_entries(pe, sink);
    let _ = codeview(pe, sink);
}

//! Minimal PE images built from scratch, for tests and fuzz seeds.
//!
//! [`SynthPe`] lays out headers and sections; [`sample`] builds a small but
//! complete image (code with calls through the IAT, `.pdata`, imports,
//! exports, base relocations, a TLS callback, a CodeView record, a panic
//! location and a registry source path) and says where everything is
//! ([`Sample`]), so the crates that read PE files can test against known
//! answers without any binary from outside.

use crate::read::align_up;
use crate::{
    FILE_DLL, FILE_EXECUTABLE_IMAGE, MACHINE_AMD64, MACHINE_I386, SCN_CNT_CODE,
    SCN_CNT_INITIALIZED_DATA, SCN_MEM_DISCARDABLE, SCN_MEM_EXECUTE, SCN_MEM_READ, SCN_MEM_WRITE,
    dir,
};

/// One section of a [`SynthPe`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthSection {
    pub name: [u8; 8],
    pub rva: u32,
    /// The initialized bytes (`SizeOfRawData` is this, file-aligned).
    pub data: Vec<u8>,
    /// `VirtualSize`; raised to `data.len()` when smaller.
    pub virtual_size: u32,
    pub characteristics: u32,
}

/// A PE image to lay out ([`SynthPe::build`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthPe {
    pub machine: u16,
    pub pe32_plus: bool,
    pub characteristics: u16,
    pub image_base: u64,
    pub entry_rva: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub directories: [(u32, u32); 16],
    pub sections: Vec<SynthSection>,
    /// COFF symbols: (name, 1-based section, value, type).
    pub symbols: Vec<(String, i16, u32, u16)>,
    /// Bytes appended after the last section.
    pub overlay: Vec<u8>,
}

/// `name` as an 8-byte section name (cut at 8).
pub fn section_name(name: &str) -> [u8; 8] {
    let mut n = [0u8; 8];
    for (d, s) in n.iter_mut().zip(name.bytes()) {
        *d = s;
    }
    n
}

fn put(buf: &mut Vec<u8>, at: usize, bytes: &[u8]) {
    let end = at + bytes.len();
    if buf.len() < end {
        buf.resize(end, 0);
    }
    if let Some(dst) = buf.get_mut(at..end) {
        dst.copy_from_slice(bytes);
    }
}

fn put16(buf: &mut Vec<u8>, at: usize, v: u16) {
    put(buf, at, &v.to_le_bytes());
}

fn put32(buf: &mut Vec<u8>, at: usize, v: u32) {
    put(buf, at, &v.to_le_bytes());
}

fn put64(buf: &mut Vec<u8>, at: usize, v: u64) {
    put(buf, at, &v.to_le_bytes());
}

impl SynthPe {
    /// An empty executable for x86-64 (`pe32_plus`) or x86, with the usual
    /// alignments (0x1000 / 0x200) and image bases.
    pub fn new(pe32_plus: bool) -> SynthPe {
        SynthPe {
            machine: if pe32_plus {
                MACHINE_AMD64
            } else {
                MACHINE_I386
            },
            pe32_plus,
            characteristics: FILE_EXECUTABLE_IMAGE | if pe32_plus { 0x20 } else { 0x100 },
            image_base: if pe32_plus { 0x1_4000_0000 } else { 0x40_0000 },
            entry_rva: 0,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            directories: [(0, 0); 16],
            sections: Vec::new(),
            symbols: Vec::new(),
            overlay: Vec::new(),
        }
    }

    /// Offset of the `PE\0\0` signature.
    pub const PE_OFFSET: usize = 0x80;

    /// The file bytes.
    pub fn build(&self) -> Vec<u8> {
        let fa = u64::from(self.file_alignment.max(1));
        let sa = u64::from(self.section_alignment.max(1));
        let opt_size: usize = if self.pe32_plus { 240 } else { 224 };
        let sec_table = Self::PE_OFFSET + 24 + opt_size;
        let headers_end = sec_table + 40 * self.sections.len();
        let size_of_headers = align_up(headers_end as u64, fa) as usize;
        let mut out = vec![0u8; size_of_headers];
        put(&mut out, 0, b"MZ");
        put32(&mut out, 0x3c, Self::PE_OFFSET as u32);
        put(&mut out, Self::PE_OFFSET, b"PE\0\0");
        let fh = Self::PE_OFFSET + 4;
        put16(&mut out, fh, self.machine);
        put16(&mut out, fh + 2, self.sections.len() as u16);
        put32(&mut out, fh + 4, 0x6000_0000);
        put16(&mut out, fh + 16, opt_size as u16);
        put16(&mut out, fh + 18, self.characteristics);
        // Section data.
        let mut raw_at = size_of_headers;
        let mut raw: Vec<(usize, usize)> = Vec::new();
        for s in &self.sections {
            let len = align_up(s.data.len() as u64, fa) as usize;
            if len == 0 {
                raw.push((0, 0));
                continue;
            }
            put(&mut out, raw_at, &s.data);
            out.resize(raw_at + len, 0);
            raw.push((raw_at, len));
            raw_at += len;
        }
        let mut image_end = align_up(size_of_headers as u64, sa);
        for (i, s) in self.sections.iter().enumerate() {
            let o = sec_table + i * 40;
            let vs = s.virtual_size.max(s.data.len() as u32);
            let (ptr, len) = raw.get(i).copied().unwrap_or((0, 0));
            put(&mut out, o, &s.name);
            put32(&mut out, o + 8, vs);
            put32(&mut out, o + 12, s.rva);
            put32(&mut out, o + 16, len as u32);
            put32(&mut out, o + 20, ptr as u32);
            put32(&mut out, o + 36, s.characteristics);
            image_end = image_end.max(align_up(u64::from(s.rva) + u64::from(vs), sa));
        }
        // Optional header.
        let oh = fh + 20;
        put16(&mut out, oh, if self.pe32_plus { 0x20b } else { 0x10b });
        put(&mut out, oh + 2, &[14]);
        put32(&mut out, oh + 16, self.entry_rva);
        if let Some(code) = self
            .sections
            .iter()
            .find(|s| s.characteristics & SCN_CNT_CODE != 0)
        {
            put32(&mut out, oh + 20, code.rva);
            put32(&mut out, oh + 4, code.data.len() as u32);
        }
        if self.pe32_plus {
            put64(&mut out, oh + 24, self.image_base);
        } else {
            put32(&mut out, oh + 28, self.image_base as u32);
        }
        put32(&mut out, oh + 32, self.section_alignment);
        put32(&mut out, oh + 36, self.file_alignment);
        put16(&mut out, oh + 40, 6);
        put16(&mut out, oh + 48, 6);
        put32(&mut out, oh + 56, image_end as u32);
        put32(&mut out, oh + 60, size_of_headers as u32);
        put16(&mut out, oh + 68, 3); // console
        put16(&mut out, oh + 70, 0x8160);
        let (nrva_at, dirs_at) = if self.pe32_plus { (108, 112) } else { (92, 96) };
        put32(&mut out, oh + nrva_at, 16);
        for (i, &(rva, size)) in self.directories.iter().enumerate() {
            put32(&mut out, oh + dirs_at + i * 8, rva);
            put32(&mut out, oh + dirs_at + i * 8 + 4, size);
        }
        // COFF symbols and string table.
        if !self.symbols.is_empty() {
            let at = out.len();
            put32(&mut out, fh + 8, at as u32);
            put32(&mut out, fh + 12, self.symbols.len() as u32);
            let mut strings: Vec<u8> = vec![0; 4];
            for (i, (name, sec, value, ty)) in self.symbols.iter().enumerate() {
                let o = at + i * 18;
                if name.len() <= 8 {
                    put(&mut out, o, name.as_bytes());
                    out.resize(out.len().max(o + 18), 0);
                } else {
                    put32(&mut out, o, 0);
                    put32(&mut out, o + 4, strings.len() as u32);
                    strings.extend_from_slice(name.as_bytes());
                    strings.push(0);
                }
                put32(&mut out, o + 8, *value);
                put16(&mut out, o + 12, *sec as u16);
                put16(&mut out, o + 14, *ty);
                out.resize(out.len().max(o + 18), 0);
                if let Some(b) = out.get_mut(o + 16) {
                    *b = 2;
                }
            }
            let n = strings.len() as u32;
            put(&mut strings, 0, &n.to_le_bytes());
            out.extend_from_slice(&strings);
        }
        out.extend_from_slice(&self.overlay);
        out
    }
}

/// What [`sample`] put where (RVAs unless noted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub bytes: Vec<u8>,
    pub pe32_plus: bool,
    pub image_base: u64,
    /// `main`: calls `CreateFileW` through the IAT, then `helper` and `leaf`.
    pub main: (u32, u32),
    /// `helper`: exported as `helper` from the DLL variant.
    pub helper: (u32, u32),
    /// `leaf`: no `.pdata` entry, only reached by a direct call.
    pub leaf: u32,
    /// The TLS callback.
    pub tls_callback: u32,
    /// A `core::panic::Location` (x64: pointer, length, line 7, column 5).
    pub location: u32,
    /// The file name the location points to.
    pub location_file: &'static str,
    /// The `"hello from synth"` literal and its length.
    pub hello: (u32, u32),
    /// IAT slots: (slot RVA, `dll!name`).
    pub iat: Vec<(u32, String)>,
    /// The PDB path in the CodeView record.
    pub pdb_path: &'static str,
}

/// The registry path in [`sample`]'s `.rdata` (Windows separators).
pub const SAMPLE_CRATE_PATH: &str = "C:\\Users\\u\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\fakecrate-1.2.3\\src\\lib.rs";
/// The rustc commit in [`sample`]'s `.rdata`.
pub const SAMPLE_RUSTC_COMMIT: &str = "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4";

const TEXT: u32 = 0x1000;
const RDATA: u32 = 0x2000;
const PDATA: u32 = 0x3000;
const DATA: u32 = 0x4000;
const RELOC: u32 = 0x5000;

/// A small x86-64 (`pe32_plus`) or x86 image; a DLL with exports when
/// `dll`. See [`Sample`].
pub fn sample(pe32_plus: bool, dll: bool) -> Sample {
    let mut pe = SynthPe::new(pe32_plus);
    if dll {
        pe.characteristics |= FILE_DLL;
        pe.image_base = if pe32_plus {
            0x1_8000_0000
        } else {
            0x1000_0000
        };
    }
    let base = pe.image_base;
    let ptr = if pe32_plus { 8u32 } else { 4 };

    // .rdata layout (offsets from RDATA).
    let mut rdata: Vec<u8> = Vec::new();
    let hello_off = 0x10u32;
    put(&mut rdata, hello_off as usize, b"hello from synth");
    let file_off = 0x30u32;
    let location_file = "src\\main.rs";
    put(&mut rdata, file_off as usize, location_file.as_bytes());
    let loc_off = 0x40u32; // pointer, length, line, column
    let crate_off = 0x60u32;
    put(&mut rdata, crate_off as usize, SAMPLE_CRATE_PATH.as_bytes());
    let rustc_off = 0x100u32;
    let rustc = format!("/rustc/{SAMPLE_RUSTC_COMMIT}\\library\\core\\src\\panicking.rs");
    put(&mut rdata, rustc_off as usize, rustc.as_bytes());
    // Imports: descriptors at 0x200, ILT at 0x260, IAT at 0x2a0, names at 0x300.
    let imp_off = 0x200u32;
    let ilt_off = 0x260u32;
    let iat_off = 0x2a0u32;
    let names_off = 0x300u32;
    let dlls: [(&str, &[ImportSpec]); 2] = [
        (
            "KERNEL32.dll",
            &[
                ImportSpec::Name("CreateFileW"),
                ImportSpec::Name("ExitProcess"),
            ],
        ),
        ("WS2_32.dll", &[ImportSpec::Ordinal(115)]),
    ];
    let mut name_at = names_off;
    let mut slot = 0u32;
    let mut iat = Vec::new();
    for (d, (dll_name, funcs)) in dlls.iter().enumerate() {
        let desc = (imp_off + d as u32 * 20) as usize;
        let ilt = ilt_off + slot * ptr;
        let iat_rva = iat_off + slot * ptr;
        put32(&mut rdata, desc, RDATA + ilt);
        put32(&mut rdata, desc + 12, RDATA + name_at);
        put32(&mut rdata, desc + 16, RDATA + iat_rva);
        put(&mut rdata, name_at as usize, dll_name.as_bytes());
        name_at += dll_name.len() as u32 + 2;
        for f in funcs.iter() {
            let thunk: u64 = match f {
                ImportSpec::Name(n) => {
                    let hn = name_at;
                    put16(&mut rdata, hn as usize, 0);
                    put(&mut rdata, hn as usize + 2, n.as_bytes());
                    name_at += (n.len() as u32 + 4) & !1;
                    iat.push((RDATA + iat_off + slot * ptr, format!("{dll_name}!{n}")));
                    u64::from(RDATA + hn)
                }
                ImportSpec::Ordinal(o) => {
                    iat.push((RDATA + iat_off + slot * ptr, format!("{dll_name}!#{o}")));
                    u64::from(*o) | if pe32_plus { 1 << 63 } else { 1 << 31 }
                }
            };
            let (l, a) = (
                (ilt_off + slot * ptr) as usize,
                (iat_off + slot * ptr) as usize,
            );
            if pe32_plus {
                put64(&mut rdata, l, thunk);
                put64(&mut rdata, a, thunk);
            } else {
                put32(&mut rdata, l, thunk as u32);
                put32(&mut rdata, a, thunk as u32);
            }
            slot += 1;
        }
        slot += 1; // terminator
    }
    let create_file_slot = RDATA + iat_off;
    pe.directories[dir::IMPORT] = (RDATA + imp_off, 3 * 20);
    pe.directories[dir::IAT] = (RDATA + iat_off, slot * ptr);

    // .text
    let main = TEXT;
    let helper = TEXT + 0x40;
    let tls_cb = TEXT + 0x60;
    let leaf = TEXT + 0x80;
    let mut text: Vec<u8> = vec![0xcc; 0x90];
    let mut code: Vec<u8> = Vec::new();
    let va = |rva: u32| base + u64::from(rva);
    let rel = |from_end: u32, to: u32| (to as i64 - from_end as i64) as i32;
    let mut relocs: Vec<u32> = Vec::new();
    if pe32_plus {
        code.extend_from_slice(&[0x53, 0x48, 0x83, 0xec, 0x20]); // push rbx; sub rsp, 0x20
        // lea rcx, [rip + location]
        let at = main + code.len() as u32;
        code.extend_from_slice(&[0x48, 0x8d, 0x0d]);
        code.extend_from_slice(&rel(at + 7, RDATA + loc_off).to_le_bytes());
        // call [rip + CreateFileW slot]
        let at = main + code.len() as u32;
        code.extend_from_slice(&[0xff, 0x15]);
        code.extend_from_slice(&rel(at + 6, create_file_slot).to_le_bytes());
        let at = main + code.len() as u32;
        code.push(0xe8);
        code.extend_from_slice(&rel(at + 5, helper).to_le_bytes());
        let at = main + code.len() as u32;
        code.push(0xe8);
        code.extend_from_slice(&rel(at + 5, leaf).to_le_bytes());
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3]);
    } else {
        code.extend_from_slice(&[0x55, 0x89, 0xe5]); // push ebp; mov ebp, esp
        code.push(0x68); // push offset hello
        relocs.push(main + code.len() as u32);
        code.extend_from_slice(&(va(RDATA + hello_off) as u32).to_le_bytes());
        code.extend_from_slice(&[0xff, 0x15]); // call [CreateFileW slot]
        relocs.push(main + code.len() as u32);
        code.extend_from_slice(&(va(create_file_slot) as u32).to_le_bytes());
        let at = main + code.len() as u32;
        code.push(0xe8);
        code.extend_from_slice(&rel(at + 5, helper).to_le_bytes());
        let at = main + code.len() as u32;
        code.push(0xe8);
        code.extend_from_slice(&rel(at + 5, leaf).to_le_bytes());
        code.extend_from_slice(&[0x5d, 0xc3]); // pop ebp; ret
    }
    let main_len = code.len() as u32;
    put(&mut text, 0, &code);
    // helper: mov eax, 1; ret
    put(
        &mut text,
        (helper - TEXT) as usize,
        &[0xb8, 1, 0, 0, 0, 0xc3],
    );
    // TLS callback: ret
    put(&mut text, (tls_cb - TEXT) as usize, &[0xc3]);
    // leaf: xor eax, eax; ret
    put(&mut text, (leaf - TEXT) as usize, &[0x31, 0xc0, 0xc3]);

    // Panic location: x64 layout (pointer, length, line, column); x86:
    // (pointer, length, line, column) with 4-byte words.
    if pe32_plus {
        put64(&mut rdata, loc_off as usize, va(RDATA + file_off));
        put64(&mut rdata, loc_off as usize + 8, location_file.len() as u64);
        put32(&mut rdata, loc_off as usize + 16, 7);
        put32(&mut rdata, loc_off as usize + 20, 5);
    } else {
        put32(&mut rdata, loc_off as usize, va(RDATA + file_off) as u32);
        put32(&mut rdata, loc_off as usize + 4, location_file.len() as u32);
        put32(&mut rdata, loc_off as usize + 8, 7);
        put32(&mut rdata, loc_off as usize + 12, 5);
    }
    relocs.push(RDATA + loc_off);

    // Unwind info (version 1, nothing to undo) and a chained one.
    let unwind_off = 0x400u32;
    put(&mut rdata, unwind_off as usize, &[1, 0, 0, 0]);
    let chained_unwind = 0x408u32;
    put(
        &mut rdata,
        chained_unwind as usize,
        &[1 | (4 << 3), 0, 0, 0],
    );

    // TLS directory at 0x480, callbacks at 0x4c0.
    let tls_off = 0x480u32;
    let cbs_off = 0x4c0u32;
    let w = |buf: &mut Vec<u8>, at: u32, v: u64| {
        if pe32_plus {
            put64(buf, at as usize, v);
        } else {
            put32(buf, at as usize, v as u32);
        }
    };
    w(&mut rdata, tls_off, va(DATA));
    w(&mut rdata, tls_off + ptr, va(DATA + 8));
    w(&mut rdata, tls_off + 2 * ptr, va(DATA + 0x10));
    w(&mut rdata, tls_off + 3 * ptr, va(RDATA + cbs_off));
    w(&mut rdata, cbs_off, va(tls_cb));
    w(&mut rdata, cbs_off + ptr, 0);
    for i in 0..4 {
        relocs.push(RDATA + tls_off + i * ptr);
    }
    relocs.push(RDATA + cbs_off);
    pe.directories[dir::TLS] = (RDATA + tls_off, 4 * ptr + 8);

    // Debug directory at 0x500, CodeView record at 0x520.
    let dbg_off = 0x500u32;
    let cv_off = 0x520u32;
    let pdb_path = "C:\\Users\\u\\proj\\target\\release\\deps\\synth.pdb";
    put32(&mut rdata, dbg_off as usize + 12, 2);
    let cv_len = 24 + pdb_path.len() as u32 + 1;
    put32(&mut rdata, dbg_off as usize + 16, cv_len);
    put32(&mut rdata, dbg_off as usize + 20, RDATA + cv_off);
    // pointer_to_raw_data is patched below, once the file offset is known.
    put(&mut rdata, cv_off as usize, b"RSDS");
    put(&mut rdata, cv_off as usize + 4, &[0x11; 16]);
    put32(&mut rdata, cv_off as usize + 20, 1);
    put(&mut rdata, cv_off as usize + 24, pdb_path.as_bytes());
    rdata.push(0);
    pe.directories[dir::DEBUG] = (RDATA + dbg_off, 28);

    // Exports at 0x600 (DLL only): helper by name, main by ordinal only,
    // and a forwarder.
    if dll {
        let e = 0x600usize;
        let name = 0x680u32;
        put(
            &mut rdata,
            name as usize,
            b"synth.dll\0helper\0fwd\0NTDLL.RtlExitUserThread\0",
        );
        let helper_name = name + 10;
        let fwd_name = name + 17;
        let fwd = name + 21;
        put32(&mut rdata, e + 12, RDATA + name);
        put32(&mut rdata, e + 16, 1); // base
        put32(&mut rdata, e + 20, 3);
        put32(&mut rdata, e + 24, 2);
        put32(&mut rdata, e + 28, RDATA + 0x640);
        put32(&mut rdata, e + 32, RDATA + 0x660);
        put32(&mut rdata, e + 36, RDATA + 0x670);
        put32(&mut rdata, 0x640, helper);
        put32(&mut rdata, 0x644, main);
        put32(&mut rdata, 0x648, RDATA + fwd);
        put32(&mut rdata, 0x660, RDATA + helper_name);
        put32(&mut rdata, 0x664, RDATA + fwd_name);
        put16(&mut rdata, 0x670, 0);
        put16(&mut rdata, 0x672, 2);
        pe.directories[dir::EXPORT] = (RDATA + e as u32, 0x100);
    }
    rdata.resize(0x800, 0);

    // .pdata (x64): main, helper, a chained fragment, the TLS callback.
    let mut pdata: Vec<u8> = Vec::new();
    if pe32_plus {
        let entries = [
            (main, main + main_len, RDATA + unwind_off),
            (helper, helper + 6, RDATA + unwind_off),
            (helper + 6, helper + 8, RDATA + chained_unwind),
            (tls_cb, tls_cb + 1, RDATA + unwind_off),
        ];
        for (i, (b, e, u)) in entries.iter().enumerate() {
            put32(&mut pdata, i * 12, *b);
            put32(&mut pdata, i * 12 + 4, *e);
            put32(&mut pdata, i * 12 + 8, *u);
        }
        pe.directories[dir::EXCEPTION] = (PDATA, pdata.len() as u32);
    }

    // .reloc: one block per page.
    let mut reloc: Vec<u8> = Vec::new();
    relocs.sort_unstable();
    let kind: u16 = if pe32_plus { 10 } else { 3 };
    let mut pages: Vec<u32> = relocs.iter().map(|r| r & !0xfff).collect();
    pages.dedup();
    for page in pages {
        let entries: Vec<u16> = relocs
            .iter()
            .filter(|r| *r & !0xfff == page)
            .map(|r| (kind << 12) | (*r & 0xfff) as u16)
            .collect();
        let padded = entries.len() + entries.len() % 2;
        let at = reloc.len();
        put32(&mut reloc, at, page);
        put32(&mut reloc, at + 4, 8 + 2 * padded as u32);
        for (i, e) in entries.iter().enumerate() {
            put16(&mut reloc, at + 8 + 2 * i, *e);
        }
        reloc.resize(at + 8 + 2 * padded, 0);
    }
    pe.directories[dir::BASERELOC] = (RELOC, reloc.len() as u32);

    let rx = SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ;
    let r = SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ;
    pe.sections = vec![
        SynthSection {
            name: section_name(".text"),
            rva: TEXT,
            data: text,
            virtual_size: 0,
            characteristics: rx,
        },
        SynthSection {
            name: section_name(".rdata"),
            rva: RDATA,
            data: rdata,
            virtual_size: 0,
            characteristics: r,
        },
    ];
    if pe32_plus {
        pe.sections.push(SynthSection {
            name: section_name(".pdata"),
            rva: PDATA,
            data: pdata,
            virtual_size: 0,
            characteristics: r,
        });
    }
    pe.sections.push(SynthSection {
        name: section_name(".data"),
        rva: DATA,
        data: vec![0; 0x20],
        virtual_size: 0x100,
        characteristics: r | SCN_MEM_WRITE,
    });
    pe.sections.push(SynthSection {
        name: section_name(".reloc"),
        rva: RELOC,
        data: reloc,
        virtual_size: 0,
        characteristics: r | SCN_MEM_DISCARDABLE,
    });
    pe.entry_rva = if dll { helper } else { main };
    let mut bytes = pe.build();
    // Patch the debug entry's PointerToRawData now that .rdata is placed.
    if let Ok(file) = crate::PeFile::parse(&bytes)
        && let Some(off) = file.rva_to_offset(u64::from(RDATA + cv_off))
        && let Some(entry) = file.rva_to_offset(u64::from(RDATA + dbg_off))
    {
        let at = entry as usize + 24;
        put32(&mut bytes, at, off as u32);
    }
    Sample {
        bytes,
        pe32_plus,
        image_base: base,
        main: (main, main_len),
        helper: (helper, 6),
        leaf,
        tls_callback: tls_cb,
        location: RDATA + loc_off,
        location_file,
        hello: (RDATA + hello_off, 16),
        iat,
        pdb_path,
    }
}

enum ImportSpec {
    Name(&'static str),
    Ordinal(u16),
}

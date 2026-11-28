//! Function starts from the `.eh_frame_hdr` search table.
//!
//! On this branch `unforge_analysis::Analysis::functions` finds functions
//! only through symbols and the entry point, so a stripped binary yields
//! almost none. The unwind tables survive stripping, and the binary search
//! table in `.eh_frame_hdr` (found through `PT_GNU_EH_FRAME`) lists the
//! start of every function that has an FDE, sorted. This module reads just
//! that table: starts, no sizes (the caller bounds each function by the
//! next start). A full `.eh_frame` reader with sizes is being added to
//! `unforge-analysis` separately; once `Analysis::functions` returns FDE
//! functions, these starts only confirm what it already has (functions
//! with a known size always win, see `crate::function_starts`).
//!
//! Layout (LSB "Linux Standard Base Core Specification", section
//! "Exception Frames", `.eh_frame_hdr`):
//!
//! ```text
//! u8 version (1), u8 eh_frame_ptr_enc, u8 fde_count_enc, u8 table_enc,
//! eh_frame_ptr (eh_frame_ptr_enc), fde_count (fde_count_enc),
//! fde_count × (initial_location, fde_address) (table_enc)
//! ```
//!
//! Only the encodings toolchains write are read: fixed-size `udata2/4/8`,
//! `sdata2/4/8` and `absptr`, applied absolutely, PC-relative or
//! relative to the start of `.eh_frame_hdr` (`datarel`). Anything else
//! (and `DW_EH_PE_omit` for the count or the table) gives no starts.

use unforge_elf::consts::{PF_X, PT_GNU_EH_FRAME};
use unforge_elf::{Class, ElfFile, Endian, MemoryMap};

/// Most starts read from one table.
pub const MAX_STARTS: usize = unforge_analysis::MAX_FUNCTIONS;

const DW_EH_PE_OMIT: u8 = 0xff;

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
    endian: Endian,
    /// Address of `b[0]`.
    base: u64,
    addr_size: usize,
}

impl Cursor<'_> {
    fn fixed(&mut self, n: usize) -> Option<u64> {
        let s = self.b.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        let mut v = 0u64;
        if self.endian == Endian::Big {
            for &x in s {
                v = (v << 8) | u64::from(x);
            }
        } else {
            for &x in s.iter().rev() {
                v = (v << 8) | u64::from(x);
            }
        }
        Some(v)
    }

    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    /// Size in bytes of a fixed-size value of encoding `enc`.
    fn size_of(&self, enc: u8) -> Option<usize> {
        match enc & 0x0f {
            0x00 => Some(self.addr_size),
            0x02 | 0x0a => Some(2),
            0x03 | 0x0b => Some(4),
            0x04 | 0x0c => Some(8),
            _ => None,
        }
    }

    /// Reads one encoded pointer.
    fn pointer(&mut self, enc: u8) -> Option<u64> {
        let here = self.base.wrapping_add(self.pos as u64);
        let n = self.size_of(enc)?;
        let raw = self.fixed(n)?;
        let v = match enc & 0x0f {
            0x0a => raw as u16 as i16 as i64 as u64,
            0x0b => raw as u32 as i32 as i64 as u64,
            _ => raw,
        };
        let v = match enc & 0x70 {
            0x00 => v,
            0x10 => here.wrapping_add(v),
            0x30 => self.base.wrapping_add(v),
            _ => return None,
        };
        // DW_EH_PE_indirect (0x80) is never used for these fields.
        if enc & 0x80 != 0 {
            return None;
        }
        Some(if self.addr_size == 4 {
            v & 0xffff_ffff
        } else {
            v
        })
    }
}

/// Function starts listed in the `.eh_frame_hdr` search table of `elf`,
/// sorted, distinct, only those in executable memory, at most
/// [`MAX_STARTS`]. Empty when there is no readable table.
pub fn eh_frame_hdr_starts(elf: &ElfFile<'_>, map: &MemoryMap) -> Vec<u64> {
    let Ok(phdrs) = elf.program_headers() else {
        return Vec::new();
    };
    let Some(ph) = phdrs.iter().find(|p| p.p_type == PT_GNU_EH_FRAME) else {
        return Vec::new();
    };
    let Some(bytes) = map.bytes_at(elf.data(), ph.vaddr) else {
        return Vec::new();
    };
    let len = usize::try_from(ph.memsz.min(ph.filesz))
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let header = elf.header();
    let mut c = Cursor {
        b: bytes.get(..len).unwrap_or(bytes),
        pos: 0,
        endian: header.endian,
        base: ph.vaddr,
        addr_size: if header.class == Class::Elf32 { 4 } else { 8 },
    };
    let mut out = Vec::new();
    let (Some(1), Some(ptr_enc), Some(count_enc), Some(table_enc)) =
        (c.u8(), c.u8(), c.u8(), c.u8())
    else {
        return out;
    };
    if ptr_enc != DW_EH_PE_OMIT && c.pointer(ptr_enc).is_none() {
        return out;
    }
    if count_enc == DW_EH_PE_OMIT || table_enc == DW_EH_PE_OMIT {
        return out;
    }
    let Some(count) = c.pointer(count_enc & 0x0f) else {
        return out;
    };
    let Some(entry) = c.size_of(table_enc).and_then(|n| n.checked_mul(2)) else {
        return out;
    };
    let left = c.b.len().saturating_sub(c.pos) / entry.max(1);
    let count = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(left)
        .min(MAX_STARTS);
    let executable = |a: u64| map.backing_ref(a).is_some_and(|b| b.flags & PF_X != 0);
    out.reserve(count);
    for _ in 0..count {
        let (Some(loc), Some(_fde)) = (c.pointer(table_enc), c.pointer(table_enc)) else {
            break;
        };
        if loc != 0 && executable(loc) {
            out.push(loc);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

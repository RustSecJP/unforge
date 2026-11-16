//! Deciding the file's layout (class and byte order).
//!
//! The Linux kernel never reads `EI_CLASS` or `EI_DATA` when it loads a file:
//! the native `binfmt_elf` handler reads the header as the host's
//! `struct elfhdr`, the compat handler as `Elf32_Ehdr`, and which handler
//! accepts the file is decided by `e_machine` alone (`elf_check_arch`;
//! testdata/anomalous/LOADER_RULES.md §1, from `fs/binfmt_elf.c`
//! `load_elf_binary` and `fs/compat_binfmt_elf.c`, Linux v7.0.12). A file whose
//! `EI_CLASS`/`EI_DATA` lie therefore still runs, and a reader that trusts
//! those bytes misreads it.
//!
//! This reader decodes the ELF header in each of the four layouts that fit in
//! the file and scores each one by the clues that support it:
//!
//! | clue | weight | why |
//! |---|---|---|
//! | the header passes the Linux kernel's header checks in this layout | 12 | it is the reading the kernel runs |
//! | `e_machine` reads as a known machine in this byte order | 4 | the kernel's handler choice |
//! | Linux uses this class for that machine | 4 | same |
//! | `e_phentsize == sizeof(Phdr)` of the class | 3 | the kernel requires it (`load_elf_phdrs`) |
//! | `e_ehsize == sizeof(Ehdr)` of the class | 2 | gABI ch4 "ELF Header" |
//! | `e_shentsize == sizeof(Shdr)` of the class | 2 | gABI ch4 "ELF Header" |
//! | `EI_CLASS` names the class | 2 | what the file claims |
//! | `EI_DATA` names the byte order | 2 | what the file claims |
//! | `e_version` reads as `EV_CURRENT` in this byte order | 1 | gABI ch4 |
//!
//! "Passes the kernel's header checks" ([`Clue::KernelAccepts`]) means, read
//! in that layout: `e_type` is `ET_EXEC` or `ET_DYN`, `e_machine` is a machine
//! Linux runs in that class, `e_phentsize == sizeof(Phdr)`, `e_phnum *
//! e_phentsize` is in `1..=65536` and that many bytes at `e_phoff` are inside
//! the file (fs/binfmt_elf.c `load_elf_binary` and `load_elf_phdrs`, Linux
//! v7.0.12; LOADER_RULES.md §1). Its weight is larger than the sum of every
//! clue the kernel ignores (`e_ehsize`, `e_shentsize`, `EI_CLASS`, `EI_DATA`,
//! `e_version`: 9), so bytes the kernel never reads cannot out-vote the
//! reading the kernel actually runs.
//!
//! The weights are a heuristic of this reader, not a rule of any loader:
//! they make the machine dominate the claim, as the kernel does, and let the
//! structure sizes decide between classes for machines that Linux runs in both
//! (x86-64 with x32, MIPS, RISC-V, s390, LoongArch). The highest score wins;
//! ties are broken in favour of the layout `EI_CLASS`/`EI_DATA` claim, then
//! ELF64 before ELF32, then little- before big-endian.
//!
//! The layout counts as read from the identification bytes
//! ([`LayoutSource::Ident`]) only when the claimed layout is consistent and
//! the rest of the header (the score without the `EI_CLASS`/`EI_DATA`
//! points, [`LayoutCandidate::evidence`]) supports it strictly more than
//! every other consistent layout. Otherwise the
//! choice is an inference and is reported (see [`Layout::inference`]), also
//! when the claim won: a claim that only broke a tie, or that won although
//! the header is inconsistent in that layout, is not confirmed by the file.

use zerocopy::FromBytes;
use zerocopy::byteorder::{BigEndian, LittleEndian};

use crate::consts::*;
use crate::diag::{Alternative, Choice, Clue, Inference, InferenceSubject};
use crate::raw::{Ehdr32, Ehdr64};
use crate::{Class, Endian};

/// Machines whose ELF class on Linux this reader knows: `(e_machine, uses
/// ELF32, uses ELF64)`.
///
/// Verified in the Linux v7.0.12 source for x86 (`arch/x86/include/asm/elf.h`:
/// `EM_X86_64` native ELF64, `EM_X86_64` ELF32 for x32 and `EM_386` for ia32
/// in the compat handler) and arm64 (`arch/arm64/include/asm/elf.h`:
/// `EM_AARCH64` ELF64 only; `EM_ARM` ELF32 for compat). The other rows are the
/// classes those ports are documented to use; they were NOT checked in source
/// here.
const MACHINES: &[(u16, bool, bool)] = &[
    (EM_SPARC, true, false),
    (EM_386, true, false),
    (EM_MIPS, true, true),
    (EM_PPC, true, false),
    (EM_PPC64, false, true),
    (EM_S390, true, true),
    (EM_ARM, true, false),
    (EM_SPARCV9, false, true),
    (EM_X86_64, true, true),
    (EM_AARCH64, false, true),
    (EM_RISCV, true, true),
    (EM_LOONGARCH, true, true),
];

/// `(uses ELF32, uses ELF64)` for a machine this reader knows.
pub(crate) fn machine_classes(machine: u16) -> Option<(bool, bool)> {
    MACHINES
        .iter()
        .find(|m| m.0 == machine)
        .map(|&(_, a, b)| (a, b))
}

/// How [`Layout`] was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LayoutSource {
    /// `EI_CLASS` and `EI_DATA` are valid, the header is consistent in that
    /// layout and no other consistent layout scores as high.
    Ident,
    /// The chosen layout is the one `EI_CLASS`/`EI_DATA` claim, but the file
    /// does not confirm it: the header is inconsistent in that layout, or
    /// another consistent layout is supported as much by the rest of the
    /// header and only the claim decided.
    IdentUnconfirmed,
    /// `e_machine` is a known machine and decided the layout (in at least one
    /// of class or byte order against, or without, `EI_CLASS`/`EI_DATA`).
    Machine,
    /// Neither the identification bytes nor `e_machine` decided: the layout
    /// is the one whose structure sizes and version field fit.
    Structure,
}

/// Header fields common to both classes, as decoded in one layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeaderFields {
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

macro_rules! fields {
    ($h:expr) => {
        HeaderFields {
            e_type: $h.e_type.get(),
            e_machine: $h.e_machine.get(),
            e_version: $h.e_version.get(),
            e_entry: $h.e_entry.get().into(),
            e_phoff: $h.e_phoff.get().into(),
            e_shoff: $h.e_shoff.get().into(),
            e_flags: $h.e_flags.get(),
            e_ehsize: $h.e_ehsize.get(),
            e_phentsize: $h.e_phentsize.get(),
            e_phnum: $h.e_phnum.get(),
            e_shentsize: $h.e_shentsize.get(),
            e_shnum: $h.e_shnum.get(),
            e_shstrndx: $h.e_shstrndx.get(),
        }
    };
}

/// Decode the ELF header in the given layout, or `None` if the file is too
/// short for it.
pub(crate) fn decode_header(data: &[u8], class: Class, endian: Endian) -> Option<HeaderFields> {
    Some(match (class, endian) {
        (Class::Elf32, Endian::Little) => {
            fields!(Ehdr32::<LittleEndian>::read_from_prefix(data).ok()?.0)
        }
        (Class::Elf32, Endian::Big) => fields!(Ehdr32::<BigEndian>::read_from_prefix(data).ok()?.0),
        (Class::Elf64, Endian::Little) => {
            fields!(Ehdr64::<LittleEndian>::read_from_prefix(data).ok()?.0)
        }
        (Class::Elf64, Endian::Big) => fields!(Ehdr64::<BigEndian>::read_from_prefix(data).ok()?.0),
    })
}

/// `sizeof(Ehdr)`, `sizeof(Phdr)`, `sizeof(Shdr)` of a class (gABI ch4/ch5).
pub(crate) fn sizes(class: Class) -> (u16, u16, u16) {
    match class {
        Class::Elf32 => (52, 32, 40),
        Class::Elf64 => (64, 56, 64),
    }
}

const MAX_CLUES: usize = 9;

/// One layout the header was decoded in, and how well it fits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutCandidate {
    pub class: Class,
    pub endian: Endian,
    /// Sum of the weights of the clues (see the module documentation).
    pub score: u32,
    /// The header decodes consistently in this layout: `e_ehsize`,
    /// `e_phentsize` (unless there are no program headers) and `e_shentsize`
    /// (unless there are no sections) have this class's sizes, and if
    /// `e_machine` is a known machine in either byte order it is one in this
    /// byte order and Linux uses this class for it.
    pub consistent: bool,
    /// The part of `score` that comes from `EI_CLASS`/`EI_DATA` themselves.
    ident_points: u32,
    clues: [Option<Clue>; MAX_CLUES],
}

impl LayoutCandidate {
    /// `score` without the points of `EI_CLASS`/`EI_DATA`: how much the rest
    /// of the header supports this layout.
    pub fn evidence(&self) -> u32 {
        self.score - self.ident_points
    }

    /// The clues that support this layout.
    pub fn clues(&self) -> impl Iterator<Item = Clue> + '_ {
        self.clues.iter().flatten().copied()
    }
}

/// The layout used to read the file, and the evidence for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub class: Class,
    pub endian: Endian,
    pub source: LayoutSource,
    /// `e_ident[EI_CLASS]` and `e_ident[EI_DATA]` as found.
    pub ident_class: u8,
    pub ident_data: u8,
    /// Index into `candidates` of the chosen layout.
    chosen: usize,
    /// `[Elf32 LE, Elf32 BE, Elf64 LE, Elf64 BE]`; `None` when the file is too
    /// short to hold that class's header.
    candidates: [Option<LayoutCandidate>; 4],
}

const ORDER: [(Class, Endian); 4] = [
    (Class::Elf32, Endian::Little),
    (Class::Elf32, Endian::Big),
    (Class::Elf64, Endian::Little),
    (Class::Elf64, Endian::Big),
];

impl Layout {
    /// Every layout the header fits in, with its score.
    pub fn candidates(&self) -> impl Iterator<Item = &LayoutCandidate> {
        self.candidates.iter().flatten()
    }

    /// The chosen candidate.
    pub fn chosen(&self) -> Option<&LayoutCandidate> {
        self.candidates.get(self.chosen).and_then(Option::as_ref)
    }

    /// The layout the identification bytes claim, when both are valid.
    pub fn claimed(&self) -> Option<(Class, Endian)> {
        Some((
            ident_class(self.ident_class)?,
            ident_endian(self.ident_data)?,
        ))
    }

    /// The chosen layout was not simply read from `EI_CLASS`/`EI_DATA` (it
    /// was decided by other clues, or the claim is not confirmed by them).
    pub fn is_inferred(&self) -> bool {
        self.source != LayoutSource::Ident
    }

    /// Other layouts that are also consistent with the header (only when the
    /// layout was inferred; for [`LayoutSource::Ident`] every other
    /// consistent layout scores lower). Non-empty means the file has no
    /// unique reading.
    pub fn viable_alternatives(&self) -> impl Iterator<Item = &LayoutCandidate> {
        let inferred = self.is_inferred();
        self.candidates
            .iter()
            .enumerate()
            .filter(move |(i, _)| inferred && *i != self.chosen)
            .filter_map(|(_, c)| c.as_ref())
            .filter(|c| c.consistent)
    }

    /// The inference record, when the layout was inferred: the chosen layout,
    /// the clues for it, and every other layout that scored above zero.
    pub fn inference(&self) -> Option<Inference> {
        if !self.is_inferred() {
            return None;
        }
        let chosen = self.chosen()?;
        let mut clues: Vec<Clue> = chosen.clues().collect();
        if self.source == LayoutSource::IdentUnconfirmed {
            let tied = self.candidates().any(|c| {
                (c.class, c.endian) != (chosen.class, chosen.endian)
                    && c.consistent
                    && c.evidence() >= chosen.evidence()
            });
            clues.push(Clue::ClaimUnconfirmed {
                tie: tied,
                consistent: chosen.consistent,
            });
        }
        if ident_class(self.ident_class).is_none() {
            clues.push(Clue::InvalidIdent {
                field: "EI_CLASS",
                value: self.ident_class,
            });
        }
        if ident_endian(self.ident_data).is_none() {
            clues.push(Clue::InvalidIdent {
                field: "EI_DATA",
                value: self.ident_data,
            });
        }
        let alternatives = self
            .candidates
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != self.chosen)
            .filter_map(|(_, c)| c.as_ref())
            .filter(|c| c.score > 0)
            .map(|c| Alternative {
                choice: Choice::Layout {
                    class: c.class,
                    endian: c.endian,
                },
                viable: c.consistent,
                score: Some(c.score),
                clues: c.clues().collect(),
            })
            .collect();
        Some(Inference {
            subject: InferenceSubject::Layout,
            chosen: Choice::Layout {
                class: chosen.class,
                endian: chosen.endian,
            },
            score: Some(chosen.score),
            clues,
            alternatives,
        })
    }
}

fn ident_class(v: u8) -> Option<Class> {
    match v {
        ELFCLASS32 => Some(Class::Elf32),
        ELFCLASS64 => Some(Class::Elf64),
        _ => None,
    }
}

fn ident_endian(v: u8) -> Option<Endian> {
    match v {
        ELFDATA2LSB => Some(Endian::Little),
        ELFDATA2MSB => Some(Endian::Big),
        _ => None,
    }
}

/// Score `h`, decoded as `(class, endian)`.
/// Whether the Linux kernel's ELF loader accepts the header read in `class`
/// (see the module documentation): `e_type`, `e_machine` for the class,
/// `e_phentsize`, the `e_phnum` range and the program header table inside
/// the file (fs/binfmt_elf.c `load_elf_binary` lines 858-863 and
/// `load_elf_phdrs` lines 521-559, Linux v7.0.12). Which of the native or
/// compat handlers would run is not decided here.
fn kernel_accepts(data: &[u8], class: Class, h: &HeaderFields) -> bool {
    let (_, phentsize, _) = sizes(class);
    let uses_class = machine_classes(h.e_machine).is_some_and(|(c32, c64)| match class {
        Class::Elf32 => c32,
        Class::Elf64 => c64,
    });
    let size = u64::from(h.e_phnum) * u64::from(phentsize);
    let table_in_file = h
        .e_phoff
        .checked_add(size)
        .is_some_and(|end| end <= data.len() as u64);
    (h.e_type == ET_EXEC || h.e_type == ET_DYN)
        && uses_class
        && h.e_phentsize == phentsize
        && (1..=65536).contains(&size)
        && table_in_file
}

/// Score `h`, decoded as `(class, endian)`.
fn score(
    data: &[u8],
    class: Class,
    endian: Endian,
    h: &HeaderFields,
    machine_known_somewhere: bool,
    id_class: u8,
    id_data: u8,
) -> LayoutCandidate {
    let mut clues = [None; MAX_CLUES];
    let mut n = 0;
    let mut add = |c: Clue| {
        if let Some(slot) = clues.get_mut(n) {
            *slot = Some(c);
            n += 1;
        }
    };
    let mut score = 0;
    let (ehsize, phentsize, shentsize) = sizes(class);
    if kernel_accepts(data, class, h) {
        score += 12;
        add(Clue::KernelAccepts { class, endian });
    }
    let mut machine_ok = !machine_known_somewhere;
    if let Some((c32, c64)) = machine_classes(h.e_machine) {
        score += 4;
        add(Clue::MachineReadsAs {
            machine: h.e_machine,
            endian,
        });
        let fits = match class {
            Class::Elf32 => c32,
            Class::Elf64 => c64,
        };
        if fits {
            score += 4;
            add(Clue::MachineUsesClass {
                machine: h.e_machine,
                class,
            });
        }
        machine_ok = fits;
    }
    if h.e_phentsize == phentsize {
        score += 3;
        add(Clue::EntrySizeMatches {
            field: "e_phentsize",
            value: phentsize,
        });
    }
    if h.e_ehsize == ehsize {
        score += 2;
        add(Clue::EntrySizeMatches {
            field: "e_ehsize",
            value: ehsize,
        });
    }
    if h.e_shentsize == shentsize {
        score += 2;
        add(Clue::EntrySizeMatches {
            field: "e_shentsize",
            value: shentsize,
        });
    }
    let mut ident_points = 0;
    if ident_class(id_class) == Some(class) {
        score += 2;
        ident_points += 2;
        add(Clue::IdentClaims {
            field: "EI_CLASS",
            value: id_class,
        });
    }
    if ident_endian(id_data) == Some(endian) {
        score += 2;
        ident_points += 2;
        add(Clue::IdentClaims {
            field: "EI_DATA",
            value: id_data,
        });
    }
    if h.e_version == u32::from(EV_CURRENT) {
        score += 1;
        add(Clue::VersionIsCurrent);
    }
    let consistent = machine_ok
        && h.e_ehsize == ehsize
        && (h.e_phnum == 0 || h.e_phentsize == phentsize)
        && (h.e_shnum == 0 || h.e_shentsize == shentsize);
    LayoutCandidate {
        class,
        endian,
        score,
        consistent,
        ident_points,
        clues,
    }
}

/// Why no layout could be decided.
pub(crate) enum DetectError {
    /// The header of the claimed layout (or of every layout) does not fit.
    TooShort { needed: u64 },
    /// No clue supports any layout.
    Undetermined,
}

/// Decide the layout of `data`, which must hold at least `e_ident`.
///
/// When `EI_CLASS`/`EI_DATA` are valid but the file is too short for that
/// layout's header, the claim cannot be checked; another layout is then only
/// used if it is fully consistent, otherwise the file is reported as too
/// short (a truncated header is not evidence for a different class).
pub(crate) fn detect(data: &[u8]) -> Result<(Layout, HeaderFields), DetectError> {
    let too_short = |c: Class| DetectError::TooShort {
        needed: u64::from(sizes(c).0),
    };
    let id_class = *data.get(4).ok_or(too_short(Class::Elf32))?;
    let id_data = *data.get(5).ok_or(too_short(Class::Elf32))?;
    let decoded = ORDER.map(|(c, e)| decode_header(data, c, e));
    let machine_known_somewhere = decoded
        .iter()
        .flatten()
        .any(|h| machine_classes(h.e_machine).is_some());
    let mut candidates = [None; 4];
    for (slot, (&(c, e), h)) in candidates.iter_mut().zip(ORDER.iter().zip(&decoded)) {
        if let Some(h) = h {
            *slot = Some(score(
                data,
                c,
                e,
                h,
                machine_known_somewhere,
                id_class,
                id_data,
            ));
        }
    }
    let claimed = ident_class(id_class).zip(ident_endian(id_data));
    let claim_unreadable =
        claimed.is_some_and(|(c, _)| decode_header(data, c, Endian::Little).is_none());
    // Highest score; ties: the claimed layout, then ELF64, then little-endian.
    let rank = |i: usize, c: &LayoutCandidate| {
        let is_claimed = claimed == Some((c.class, c.endian));
        let pref = match ORDER.get(i) {
            Some((Class::Elf64, Endian::Little)) => 3,
            Some((Class::Elf64, Endian::Big)) => 2,
            Some((Class::Elf32, Endian::Little)) => 1,
            _ => 0,
        };
        (c.score, is_claimed, pref)
    };
    let best = candidates
        .iter()
        .enumerate()
        .filter_map(|(i, c)| c.as_ref().map(|c| (i, c)))
        .filter(|(_, c)| !claim_unreadable || c.consistent)
        .max_by_key(|(i, c)| rank(*i, c));
    let (chosen, best) = match best {
        Some(b) if b.1.score > 0 => b,
        _ => {
            return Err(match claimed {
                Some((c, _)) if claim_unreadable => too_short(c),
                _ if decoded.iter().all(Option::is_none) => too_short(Class::Elf32),
                _ => DetectError::Undetermined,
            });
        }
    };
    let (class, endian) = (best.class, best.endian);
    let machine_decides = best
        .clues()
        .any(|c| matches!(c, Clue::MachineReadsAs { .. }));
    // The claim is confirmed only when its layout is consistent and the
    // rest of the header supports it more than every other consistent
    // layout (the claim does not count as evidence for itself).
    let confirmed = best.consistent
        && candidates
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != chosen)
            .filter_map(|(_, c)| c.as_ref())
            .all(|c| !c.consistent || c.evidence() < best.evidence());
    let source = if claimed == Some((class, endian)) {
        if confirmed {
            LayoutSource::Ident
        } else {
            LayoutSource::IdentUnconfirmed
        }
    } else if machine_decides {
        LayoutSource::Machine
    } else {
        LayoutSource::Structure
    };
    let fields = decoded
        .get(chosen)
        .copied()
        .flatten()
        .ok_or(DetectError::Undetermined)?;
    Ok((
        Layout {
            class,
            endian,
            source,
            ident_class: id_class,
            ident_data: id_data,
            chosen,
            candidates,
        },
        fields,
    ))
}

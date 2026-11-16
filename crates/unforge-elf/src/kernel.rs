//! Predicting what the Linux kernel's native ELF loader does with a file.
//!
//! Model: `fs/binfmt_elf.c` `load_elf_binary`, `load_elf_phdrs`, `elf_map`,
//! `elf_load`, `padzero`, `parse_elf_properties` and `parse_elf_property` of
//! Linux v7.0.12 (commit f53879e2e1e2fa053040e734c1ef8f386109a61b), plus
//! `fs/exec.c` `prepare_binprm` (the first 256 bytes, zero-filled past the end
//! of the file) and `mm/util.c` `vm_mmap` (unaligned offset -> `-EINVAL`).
//! testdata/anomalous/LOADER_RULES.md lists the rules with line numbers.
//!
//! The prediction reads the raw bytes in the host's native layout, never
//! `EI_CLASS`/`EI_DATA`, exactly like the native handler.
//!
//! NOT modelled (the prediction says `Loads` for these):
//! - the file system: a missing `PT_INTERP` target (`ENOENT`), the
//!   interpreter's own header (`ELIBBAD`, and its `e_type`, checked after the
//!   point of no return), and the interpreter's `PT_GNU_PROPERTY`;
//! - the compat (32-bit) handler and `binfmt_misc`, which may accept a file
//!   the native handler refuses;
//! - `MAP_FIXED_NOREPLACE` collisions, `vm_brk` failures, resource limits;
//! - the `ET_DYN` load bias: address checks use the unbiased `p_vaddr`, as
//!   `load_elf_binary` does for `p_vaddr`, and the entry check is done only
//!   for `ET_EXEC` (whose bias is 0).

use core::fmt;

use zerocopy::FromBytes;
use zerocopy::byteorder::{LittleEndian, U16, U32, U64};

use crate::consts::*;

/// A host the prediction is made for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelHost {
    /// The native `e_machine` (`elf_check_arch`).
    pub machine: u16,
    /// `ELF_MIN_ALIGN` = max(`ELF_EXEC_PAGESIZE`, `PAGE_SIZE`). Must be a
    /// power of two.
    pub page_size: u64,
    /// `TASK_SIZE` of a native process.
    pub task_size: u64,
    /// `CONFIG_ARCH_USE_GNU_PROPERTY` (arm64: yes, x86: no in v7.0.12).
    pub gnu_property: bool,
}

impl KernelHost {
    /// The hosts this model covers, with 4 KiB pages: `EM_AARCH64`
    /// (`TASK_SIZE` 2^48, i.e. `VA_BITS` = 48) and `EM_X86_64` (`TASK_SIZE`
    /// 2^47 - 4096, 4-level paging). A kernel with other pages or address
    /// widths needs its own `KernelHost`; neither value was read from the
    /// configuration of the linuxkit kernel used for the corpus verdicts.
    pub fn for_machine(machine: u16) -> Option<KernelHost> {
        match machine {
            EM_AARCH64 => Some(KernelHost {
                machine,
                page_size: 4096,
                task_size: 1 << 48,
                gnu_property: true,
            }),
            EM_X86_64 => Some(KernelHost {
                machine,
                page_size: 4096,
                task_size: (1 << 47) - 4096,
                gnu_property: false,
            }),
            _ => None,
        }
    }
}

/// One rule the kernel enforces (LOADER_RULES.md §5), with the values that
/// broke it. `index` is an index into the program header table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KernelRule {
    BadMagic,
    BadType(u16),
    BadMachine(u16),
    PhentsizeMismatch {
        found: u16,
        expected: u16,
    },
    /// `e_phnum * sizeof(Phdr)` not in `1..=65536` (`PN_XNUM` is used
    /// literally).
    PhnumOutOfRange(u16),
    /// The program header table is not entirely inside the file.
    PhdrsOutsideFile,
    /// `PT_INTERP` `p_filesz` not in `2..=PATH_MAX`.
    InterpSize(u64),
    /// The `PT_INTERP` bytes are not entirely inside the file.
    InterpOutsideFile,
    /// The last `PT_INTERP` byte is not NUL.
    InterpNotTerminated,
    /// `PT_GNU_PROPERTY` is malformed (arm64 only).
    GnuPropertyMalformed,
    /// `ET_DYN` whose `PT_LOAD`s span no memory (`total_mapping_size` 0).
    EmptyMapping {
        index: usize,
    },
    /// `p_offset` not congruent to `p_vaddr` modulo the page size
    /// (`p_filesz > 0`).
    OffsetVaddrNotCongruent {
        index: usize,
    },
    /// Writable `PT_LOAD` with `p_memsz > p_filesz` whose last file page is
    /// past the end of the file: `padzero()` fails with `-EFAULT`.
    PaddingFault {
        index: usize,
    },
    FileszExceedsMemsz {
        index: usize,
    },
    /// `p_vaddr` / `p_memsz` (with `index`) or `e_entry` (`None`) at or above
    /// `TASK_SIZE`.
    AddressAboveTaskSize {
        index: Option<usize>,
    },
}

/// The kernel's verdict on a file, predicted from the bytes alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KernelPrediction {
    /// `execve` maps the file and starts user space (or the interpreter).
    /// Says nothing about whether the program then works.
    Loads,
    /// `execve` returns an errno: the rule failed before `begin_new_exec()`.
    RejectedAtExec(KernelRule),
    /// The rule fails after the point of no return: the process is killed
    /// with `SIGSEGV` (fs/exec.c `bprm_execve`, `force_fatal_sig`).
    AbortedAfterPointOfNoReturn(KernelRule),
    /// No model for this host machine.
    NotModelled { host_machine: u16 },
}

impl fmt::Display for KernelPrediction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelPrediction::Loads => write!(f, "loads"),
            KernelPrediction::RejectedAtExec(r) => write!(f, "execve fails: {r:?}"),
            KernelPrediction::AbortedAfterPointOfNoReturn(r) => {
                write!(f, "killed with SIGSEGV after the point of no return: {r:?}")
            }
            KernelPrediction::NotModelled { host_machine } => {
                write!(f, "no model for host machine {host_machine}")
            }
        }
    }
}

const BINPRM_BUF_SIZE: usize = 256;
const PATH_MAX: u64 = 4096;
const PHDR64: u64 = 56;

/// A little-endian ELF64 view of the raw bytes (both modelled hosts are
/// ELF64 little-endian).
struct Raw<'a> {
    data: &'a [u8],
}

impl Raw<'_> {
    fn u16(&self, o: u64) -> Option<u16> {
        let b = self.data.get(usize::try_from(o).ok()?..)?;
        Some(U16::<LittleEndian>::read_from_prefix(b).ok()?.0.get())
    }
    fn u32(&self, o: u64) -> Option<u32> {
        let b = self.data.get(usize::try_from(o).ok()?..)?;
        Some(U32::<LittleEndian>::read_from_prefix(b).ok()?.0.get())
    }
    fn u64(&self, o: u64) -> Option<u64> {
        let b = self.data.get(usize::try_from(o).ok()?..)?;
        Some(U64::<LittleEndian>::read_from_prefix(b).ok()?.0.get())
    }
    /// `count` bytes at `o`, entirely inside the file (`elf_read` fails on a
    /// short read).
    fn bytes(&self, o: u64, count: u64) -> Option<&[u8]> {
        let s = usize::try_from(o).ok()?;
        let e = s.checked_add(usize::try_from(count).ok()?)?;
        self.data.get(s..e)
    }
}

#[derive(Clone, Copy)]
struct Ph {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

fn ph(table: &Raw<'_>, i: u64) -> Option<Ph> {
    let b = i.checked_mul(PHDR64)?;
    Some(Ph {
        p_type: table.u32(b)?,
        flags: table.u32(b + 4)?,
        offset: table.u64(b + 8)?,
        vaddr: table.u64(b + 16)?,
        filesz: table.u64(b + 32)?,
        memsz: table.u64(b + 40)?,
    })
}

/// See [`crate::ElfFile::kernel_prediction_with`].
pub(crate) fn predict(data: &[u8], host: &KernelHost) -> KernelPrediction {
    use KernelPrediction::{AbortedAfterPointOfNoReturn as Abort, Loads, RejectedAtExec as Reject};
    use KernelRule as R;
    if KernelHost::for_machine(host.machine).is_none() || !host.page_size.is_power_of_two() {
        return KernelPrediction::NotModelled {
            host_machine: host.machine,
        };
    }
    // bprm->buf: the first 256 bytes, zero-filled past the end of the file
    // (fs/exec.c prepare_binprm: memset, then kernel_read).
    let mut buf = [0u8; BINPRM_BUF_SIZE];
    let n = data.len().min(BINPRM_BUF_SIZE);
    if let (Some(dst), Some(src)) = (buf.get_mut(..n), data.get(..n)) {
        dst.copy_from_slice(src);
    }
    let eh = Raw { data: &buf };
    let file = Raw { data };

    if buf.get(..4) != Some(&ELFMAG[..]) {
        return Reject(R::BadMagic);
    }
    let e_type = eh.u16(0x10).unwrap_or(0);
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Reject(R::BadType(e_type));
    }
    let machine = eh.u16(0x12).unwrap_or(0);
    if machine != host.machine {
        return Reject(R::BadMachine(machine));
    }
    let entry = eh.u64(0x18).unwrap_or(0);
    let phoff = eh.u64(0x20).unwrap_or(0);
    let phentsize = eh.u16(0x36).unwrap_or(0);
    let phnum = eh.u16(0x38).unwrap_or(0);

    // load_elf_phdrs
    if u64::from(phentsize) != PHDR64 {
        return Reject(R::PhentsizeMismatch {
            found: phentsize,
            expected: PHDR64 as u16,
        });
    }
    let size = PHDR64 * u64::from(phnum);
    if size == 0 || size > 65536 {
        return Reject(R::PhnumOutOfRange(phnum));
    }
    let Some(table) = file.bytes(phoff, size) else {
        return Reject(R::PhdrsOutsideFile);
    };
    let table = Raw { data: table };
    let phs = || (0..u64::from(phnum)).filter_map(|i| ph(&table, i));

    // The PT_INTERP loop, which also records PT_GNU_PROPERTY entries seen
    // before the first PT_INTERP (it `break`s after the interpreter).
    let mut property = None;
    let mut interp = false;
    for p in phs() {
        if p.p_type == PT_GNU_PROPERTY {
            property = Some(p);
            continue;
        }
        if p.p_type != PT_INTERP {
            continue;
        }
        if p.filesz > PATH_MAX || p.filesz < 2 {
            return Reject(R::InterpSize(p.filesz));
        }
        let Some(path) = file.bytes(p.offset, p.filesz) else {
            return Reject(R::InterpOutsideFile);
        };
        if path.last() != Some(&0) {
            return Reject(R::InterpNotTerminated);
        }
        // open_exec and the interpreter's header: not modelled.
        interp = true;
        break;
    }
    // With an interpreter, the kernel parses the interpreter's property
    // note, not the program's (not modelled).
    if host.gnu_property
        && !interp
        && let Some(p) = property
        && !gnu_property_ok(&file, p)
    {
        return Reject(R::GnuPropertyMalformed);
    }

    // begin_new_exec(): the point of no return.
    let page = host.page_size;
    let pageoff = |v: u64| v & (page - 1);
    let mut first = true;
    for (i, p) in phs().enumerate() {
        if p.p_type != PT_LOAD {
            continue;
        }
        if first && e_type == ET_DYN && total_mapping_size(phs(), page) == 0 {
            return Abort(R::EmptyMapping { index: i });
        }
        first = false;
        // elf_load -> elf_map -> vm_mmap: the file offset passed is
        // p_offset - PAGEOFFSET(p_vaddr), which must be page aligned.
        if p.filesz != 0 {
            let off = p.offset.wrapping_sub(pageoff(p.vaddr));
            if pageoff(off) != 0 {
                return Abort(R::OffsetVaddrNotCongruent { index: i });
            }
            // padzero(zero_start) for a writable segment: clearing the rest
            // of the last file page faults when that page is past EOF.
            if p.memsz > p.filesz && p.flags & PF_W != 0 {
                let end = p.offset.wrapping_add(p.filesz);
                if pageoff(end) != 0 && end & !(page - 1) >= data.len() as u64 {
                    return Abort(R::PaddingFault { index: i });
                }
            }
        }
        let task = host.task_size;
        if p.vaddr >= task || p.filesz > p.memsz || p.memsz > task || task - p.memsz < p.vaddr {
            return Abort(if p.filesz > p.memsz {
                R::FileszExceedsMemsz { index: i }
            } else {
                R::AddressAboveTaskSize { index: Some(i) }
            });
        }
    }
    if !interp && e_type == ET_EXEC && entry >= host.task_size {
        return Abort(R::AddressAboveTaskSize { index: None });
    }
    Loads
}

/// fs/binfmt_elf.c `total_mapping_size`.
fn total_mapping_size(phs: impl Iterator<Item = Ph>, page: u64) -> u64 {
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut any = false;
    for p in phs.filter(|p| p.p_type == PT_LOAD) {
        min = min.min(p.vaddr & !(page - 1));
        max = max.max(p.vaddr.wrapping_add(p.memsz));
        any = true;
    }
    if any { max.wrapping_sub(min) } else { 0 }
}

/// fs/binfmt_elf.c `parse_elf_properties` / `parse_elf_property` and arm64
/// `arch_parse_elf_property` (`GNU_PROPERTY_AARCH64_FEATURE_1_AND` must have
/// `pr_datasz == 4`). ELF64: `ELF_GNU_PROPERTY_ALIGN` is 8.
fn gnu_property_ok(file: &Raw<'_>, p: Ph) -> bool {
    const NOTE_DATA_SZ: u64 = 1024;
    const NHDR: usize = 12;
    const NAME_SZ: usize = 4;
    const ALIGN: usize = 8;
    if p.filesz > NOTE_DATA_SZ {
        return false;
    }
    // kernel_read may return fewer bytes at EOF; `n` is what was read.
    let start = usize::try_from(p.offset).unwrap_or(usize::MAX);
    let want = usize::try_from(p.filesz).unwrap_or(0);
    let note = file
        .data
        .get(start..)
        .map(|b| b.get(..want).unwrap_or(b))
        .unwrap_or(&[]);
    let n = note.len();
    if n < NHDR + NAME_SZ {
        return false; // -EIO
    }
    let r = Raw { data: note };
    let (namesz, descsz, ntype) = (
        r.u32(0).unwrap_or(0),
        r.u32(4).unwrap_or(0),
        r.u32(8).unwrap_or(0),
    );
    // strncmp(name, "GNU", n - 12): compares up to the NUL of "GNU".
    if ntype != NT_GNU_PROPERTY_TYPE_0
        || namesz as usize != NAME_SZ
        || note.get(NHDR..NHDR + NAME_SZ) != Some(&b"GNU\0"[..])
    {
        return false;
    }
    let mut off = (NHDR + NAME_SZ).div_ceil(ALIGN) * ALIGN;
    if off > n || descsz as usize > n - off {
        return false;
    }
    let datasz = off + descsz as usize;
    let mut prev: Option<u32> = None;
    loop {
        if off == datasz {
            return true; // -ENOENT: done
        }
        if off > datasz || !off.is_multiple_of(ALIGN) {
            return false;
        }
        let rest = datasz - off;
        if rest < 8 {
            return false;
        }
        let (Some(pr_type), Some(pr_datasz)) = (r.u32(off as u64), r.u32(off as u64 + 4)) else {
            return false;
        };
        let o = off + 8;
        let rest = rest - 8;
        if pr_datasz as usize > rest {
            return false;
        }
        let step = (pr_datasz as usize).div_ceil(ALIGN) * ALIGN;
        if step > rest {
            return false;
        }
        if prev.is_some_and(|p| pr_type <= p) {
            return false;
        }
        prev = Some(pr_type);
        if pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND && pr_datasz != 4 {
            return false;
        }
        off = o + step;
    }
}

impl crate::ElfFile<'_> {
    /// The kernel's verdict for a host whose native machine is
    /// `host_machine`, with the defaults of [`KernelHost::for_machine`].
    /// Works on any bytes, including files `parse` refuses.
    pub fn kernel_prediction_for(data: &[u8], host_machine: u16) -> KernelPrediction {
        match KernelHost::for_machine(host_machine) {
            Some(h) => predict(data, &h),
            None => KernelPrediction::NotModelled { host_machine },
        }
    }

    /// The kernel's verdict for `host`. See the module documentation of
    /// what is and is not modelled.
    pub fn kernel_prediction_with(data: &[u8], host: &KernelHost) -> KernelPrediction {
        predict(data, host)
    }
}

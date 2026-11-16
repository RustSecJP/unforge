# What the Linux loaders actually check

This document records, from source, which ELF fields the Linux kernel ELF
loader (`binfmt_elf`) and the two common dynamic loaders (glibc `ld.so`,
musl `ldso`) check, what they ignore, and what happens on failure. It is the
reference for the "tolerant" reading mode of `unforge-elf`: a field that the
kernel ignores must never be a hard parse error, because a file that the
kernel runs is exactly the file an analyst most needs to read.

## Sources

All line numbers below refer to these exact trees.

| Project | Version | Commit | Files read |
|---|---|---|---|
| Linux (stable) | v7.0.12 | `f53879e2e1e2fa053040e734c1ef8f386109a61b` | `fs/binfmt_elf.c`, `fs/exec.c`, `fs/compat_binfmt_elf.c`, `mm/util.c`, `include/linux/elf.h`, `include/uapi/linux/binfmts.h`, `arch/arm64/include/asm/elf.h`, `arch/arm64/kernel/process.c`, `arch/x86/include/asm/elf.h`, `arch/arm64/Kconfig`, `arch/x86/Kconfig` |
| glibc | 2.44 (tag `glibc-2.44`) | `c3a3a9808ad3ab4a3336836833f83288b672ccbf` | `elf/dl-load.c`, `elf/dl-load.h`, `elf/dl-map-segments.h`, `elf/rtld.c`, `elf/get-dynamic-info.h`, `elf/dl-setup_hash.c`, `elf/dl-deps.c`, `sysdeps/gnu/ldsodefs.h`, `sysdeps/{aarch64,x86_64}/dl-machine.h`, `sysdeps/unix/sysv/linux/dl-sysdep.c` |
| musl | 1.2.6 | `9fa28ece75d8a2191de7c5bb53bed224c5947417` | `ldso/dynlink.c` |
| gABI | latest | — | https://www.sco.com/developers/gabi/latest/ (ch4 ELF header, ch5 program header) |

The kernel used for local experiments is Docker Desktop's linuxkit
`7.0.12-linuxkit` (aarch64). Only `linux/arm64` containers run a file through
the real kernel `binfmt_elf`. `linux/amd64` containers run x86-64 files through
a user-mode emulator registered via `binfmt_misc` (Rosetta or qemu-user); their
verdict is the emulator's ELF loader and must never be reported as a kernel
verdict. Nothing in this document was derived from an amd64-container run.

Page size: `ELF_MIN_ALIGN` is `max(ELF_EXEC_PAGESIZE, PAGE_SIZE)`
(`fs/binfmt_elf.c:82-86`). On x86-64 it is 4096. On arm64 it is the kernel's
`PAGE_SIZE` (4 KiB, 16 KiB or 64 KiB depending on config). The page size of the
linuxkit kernel was not checked in its config; treat "page" below as
"the running kernel's page size".

## How a failure surfaces

The kernel loader has two kinds of failure, and the distinction matters for any
experiment that runs a crafted file:

| Phase | When | What the caller sees | Source |
|---|---|---|---|
| Before the point of no return | Any error before `begin_new_exec()` (`fs/binfmt_elf.c:1011`) | `execve()` returns the error (`ENOEXEC`, `ELIBBAD`, `EIO`, `ENOENT`, ...). For `ENOEXEC` only, the next registered binfmt handler is tried (`fs/exec.c:search_binary_handler`, lines 1645-1676); if none accepts, `execve` fails with `ENOEXEC`. Shells (POSIX `sh`) then often run the file as a shell script, so use a direct `execve` wrapper, not `sh -c ./file`, when testing. | `fs/exec.c:1668` |
| After the point of no return | Any error after `begin_new_exec()` sets `bprm->point_of_no_return` (`fs/exec.c:1112`) | The process is killed with `SIGSEGV` (`fs/exec.c:1768-1769`, `force_fatal_sig`). `execve` never returns. | |
| At run time | The image loaded but is not sane (entry not mapped, bad phdr address for ld.so, ...) | Ordinary crash (`SIGSEGV`/`SIGBUS`/`SIGILL`) or an ld.so error message and exit code 127. | |

Below, "ENOEXEC (pre)" means rejected before the point of no return,
"SIGSEGV (post)" means killed after it.

## 1. Kernel: ELF header (`Elf64_Ehdr` / `Elf32_Ehdr`)

The kernel reads the first `BINPRM_BUF_SIZE` = 256 bytes of the file into
`bprm->buf` (`fs/exec.c:prepare_binprm`, line 1603;
`include/uapi/linux/binfmts.h:19`) and casts it to the native `struct elfhdr`
(`fs/binfmt_elf.c:854`). It does **not** look at `EI_CLASS` to choose the
layout: the native handler always uses the native class, and the compat
handler (`fs/compat_binfmt_elf.c`, `ELF_CLASS` = `ELFCLASS32` at line 26)
always uses the 32-bit layout. Which handler accepts a file is decided only by
`elf_check_arch` / `compat_elf_check_arch`.

| Field | Condition checked | Consequence | Source (v7.0.12) |
|---|---|---|---|
| `e_ident[0..4]` magic | must equal `\x7fELF` | ENOEXEC (pre) | `fs/binfmt_elf.c:load_elf_binary:858` |
| `e_ident[EI_CLASS]` | **not checked** | ignored. The layout is implied by which handler runs, not by this byte. | grep: no `EI_CLASS` use in the load path; only the core dumper writes it (`:1444`) |
| `e_ident[EI_DATA]` | **not checked** | ignored. Fields are read in host byte order. A big-endian file on a little-endian host fails only indirectly, because its `e_machine` then reads as a byte-swapped value. | same grep (`:1445` is the core dumper) |
| `e_ident[EI_VERSION]` | **not checked** | ignored | same grep (`:1446`) |
| `e_ident[EI_OSABI]` | **not checked** | ignored | same grep (`:1447`) |
| `e_ident[EI_ABIVERSION]`, `e_ident[EI_PAD..16]` | **not checked** | ignored | only `memcmp(e_ident, ELFMAG, SELFMAG)` touches `e_ident` (`:858`, `:962`) |
| `e_type` | must be `ET_EXEC` (2) or `ET_DYN` (3) | ENOEXEC (pre). `ET_REL`, `ET_CORE`, OS/proc-specific values are rejected. | `:861` |
| `e_machine` | x86-64 native: `== EM_X86_64` (62). arm64 native: `== EM_AARCH64` (183). | ENOEXEC (pre) | `:863`; `arch/x86/include/asm/elf.h:146-147`; `arch/arm64/include/asm/elf.h:97` |
| `e_machine` (compat, 32-bit) | x86-64: `EM_386`/`EM_486` (if ia32 is enabled) or `EM_X86_64` (x32, if `CONFIG_X86_X32_ABI`). arm64: `EM_ARM` and `e_flags & EF_ARM_EABI_MASK != 0` and the CPU supports AArch32 EL0. | ENOEXEC (pre) | `arch/x86/include/asm/elf.h:149-151`; `arch/arm64/kernel/process.c:compat_elf_check_arch:788-798` |
| `e_version` | **not checked** | ignored | grep: no `e_version` read in the load path (`:1451` is the core dumper) |
| `e_entry` | after adding the load bias: `< TASK_SIZE` | SIGSEGV (post) if `>= TASK_SIZE`. It is **not** checked to lie inside any `PT_LOAD`; an unmapped entry just crashes at run time. With an interpreter, the interpreter's `e_entry` is jumped to and the program's `e_entry` is only passed as `AT_ENTRY`. | `:1246`, `:1265-1269`, `:1281`; `BAD_ADDR` at `:105` |
| `e_phoff` | the read of `e_phnum * sizeof(phdr)` bytes at this file offset must fully succeed | short read -> `-EIO` inside `load_elf_phdrs`, reported as ENOEXEC (pre). No alignment requirement. | `load_elf_phdrs:521-559`, `elf_read:481-490` |
| `e_phentsize` | must equal `sizeof(struct elf_phdr)` (56 for ELF64, 32 for ELF32) | ENOEXEC (pre) | `load_elf_phdrs:532` |
| `e_phnum` | `e_phnum * sizeof(phdr)` must be in `1..=65536`; i.e. 1..=1170 (ELF64), 1..=2048 (ELF32). `PN_XNUM` (0xffff) extended numbering is **not supported** for loading; `e_phnum` is used literally. | ENOEXEC (pre) | `load_elf_phdrs:537-539` |
| `e_flags` | native: **not checked** (only saved for core dumps). compat arm: EABI bits must be non-zero. | ignored (native) | `:1309`, `:107-112` |
| `e_ehsize` | **not checked** | ignored | grep: no `e_ehsize` read in load path |
| `e_shoff`, `e_shentsize`, `e_shnum`, `e_shstrndx` | **not read at all** | ignored. Section headers may be absent, truncated, zeroed or garbage. | grep: `e_sh*` only appears in the core dumper (`fill_extnum_info:1971-1984`) |

Interpreter (`PT_INTERP` target) header, checked in `load_elf_binary` and
`load_elf_interp`:

| Field | Condition | Consequence | Source |
|---|---|---|---|
| magic | `\x7fELF` | ELIBBAD (pre) | `:960-963` |
| `e_machine` | same `elf_check_arch` as above, and not FDPIC | ELIBBAD (pre) | `:965-967` |
| `e_phentsize`, `e_phnum`, `e_phoff` | same `load_elf_phdrs` rules | ELIBBAD (pre) | `:970-973` |
| `e_type` | `ET_EXEC` or `ET_DYN` | SIGSEGV (post): this check is in `load_elf_interp`, which runs after the point of no return | `load_elf_interp:659-661` |
| `EI_CLASS`/`EI_DATA`/`EI_VERSION`/`EI_OSABI`/padding/`e_version` | not checked | ignored | |
| at least one `PT_LOAD` | `total_mapping_size() != 0` | SIGSEGV (post) | `load_elf_interp:667-672` |

## 2. Kernel: program headers

Program headers are read once from the file at `e_phoff` (not from mapped
memory). Only these `p_type` values are acted on by the generic loader:
`PT_LOAD`, `PT_INTERP`, `PT_GNU_STACK`, `PT_GNU_PROPERTY`, and
`PT_LOPROC..PT_HIPROC` (passed to the arch hook, which is a no-op on arm64,
`arch/arm64/include/asm/elf.h:282-287`). Everything else, including
`PT_PHDR`, `PT_DYNAMIC`, `PT_TLS`, `PT_NOTE`, `PT_GNU_RELRO`,
`PT_GNU_EH_FRAME`, and any unknown type, is **ignored** by the kernel.

### PT_LOAD

| Aspect | Rule in source | Consequence | Source |
|---|---|---|---|
| Count | ET_DYN: at least one `PT_LOAD` (`total_mapping_size != 0`). ET_EXEC: zero `PT_LOAD` is not rejected by the loader. | ET_DYN without PT_LOAD: `-EINVAL`, SIGSEGV (post). ET_EXEC without PT_LOAD: loads, then crashes at the unmapped entry. | `:1100-1104`, `total_mapping_size:464-479` |
| Ordering by `p_vaddr` | **not checked**. gABI requires ascending order, the kernel does not enforce it. The *first* `PT_LOAD` in table order fixes the load bias (`load_bias = PAGESTART(base - first.p_vaddr)`); `total_mapping_size` uses min/max over all PT_LOADs. | accepted. Out-of-order segments may be mapped outside the reserved range (later ones use `MAP_FIXED`). | `:1066-1075`, `:1179`, `:1188-1195` |
| Overlap between PT_LOADs | **not checked**. The first PT_LOAD is mapped with `MAP_FIXED_NOREPLACE` (ET_EXEC, or ET_DYN with interpreter/large alignment); every later one with `MAP_FIXED`, which silently replaces earlier mappings. | accepted; the later segment wins for the overlapping pages. | `:1065-1066` |
| First PT_LOAD colliding with an existing mapping | `MAP_FIXED_NOREPLACE` fails with `EEXIST` | SIGSEGV (post), with a `pr_info` "Uhuuh, elf segment at ... requested but the memory is mapped already" | `elf_map:401-404` |
| `p_offset` vs `p_vaddr` | `(p_offset - (p_vaddr % page))` must be page aligned, i.e. `p_offset ≡ p_vaddr (mod page size)`. This is enforced only indirectly, by `vm_mmap` returning `-EINVAL` for an unaligned file offset, and only when `p_filesz != 0`. | SIGSEGV (post) | `elf_map:376-377`; `mm/util.c:vm_mmap:614-615` |
| `p_offset % p_align == p_vaddr % p_align` (gABI) | **not checked**. Only the page-size congruence above matters. | accepted | |
| `p_align` | Used only for ET_DYN, to align the load bias to the largest power-of-two `p_align` among PT_LOADs. Non-power-of-two values (including 0) are skipped silently. No minimum. | ignored if not a power of two | `maximum_alignment:492-509`, `:1108`, `:1144-1145` |
| `p_filesz > p_memsz` | rejected | `-EINVAL`, SIGSEGV (post). Checked *after* the segment is mapped. | `:1227-1232` (main), `load_elf_interp:709-714` (interp, `-ENOMEM`) |
| `p_memsz` / `p_vaddr` range | `p_vaddr` (+bias) `< TASK_SIZE`, `p_memsz <= TASK_SIZE`, `p_vaddr + p_memsz <= TASK_SIZE` | SIGSEGV (post) | `:1227-1229` |
| `p_filesz == 0` | allowed: nothing is mapped from the file, the whole `p_memsz` is anonymous zero memory | accepted | `elf_load:422-441`, `elf_map:381-384` |
| `p_offset + p_filesz` beyond end of file | **not checked by the loader**. `mmap` of a file range past EOF succeeds; touching those pages gives `SIGBUS`. If `p_memsz > p_filesz` and the segment is writable, `padzero()` writes into the last file page and may fail with `-EFAULT`. Exact behaviour for this case was not verified by experiment. | not rejected up front | `elf_load:426-437`, `padzero:127` |
| `p_flags` | converted to `PROT_*` by `make_prot`; no validation | used | `make_prot:626-639` |

### Program header table and ELF header inside a PT_LOAD

| Question | Answer | Source |
|---|---|---|
| Must the ELF header be inside a PT_LOAD? | No. The kernel reads it from the file; nothing requires it to be mapped. | `fs/exec.c:1603` |
| Must the program header table be inside a PT_LOAD? | No. If it is, `AT_PHDR` = its mapped address. The test is `p_offset <= e_phoff < p_offset + p_filesz` (start only, not the whole table), and the *last* matching PT_LOAD wins (no `break`). If no PT_LOAD contains it, `AT_PHDR` is just `load_bias + 0`, which is a bogus pointer that the dynamic loader will then dereference. | `:1210-1214`, `:1247`, `create_elf_tables` (`NEW_AUX_ENT(AT_PHDR, ...)`) |
| Is `PT_PHDR` used by the kernel? | No. `AT_PHDR` is computed from `e_phoff` and the PT_LOADs, never from `PT_PHDR`. | grep: no `PT_PHDR` in `fs/binfmt_elf.c` |
| `AT_PHENT`, `AT_PHNUM` | `sizeof(struct elf_phdr)` and `e_phnum` | `create_elf_tables` |

### PT_INTERP

| Rule | Consequence | Source |
|---|---|---|
| Only the **first** `PT_INTERP` in table order is used (`break` after it) | later ones ignored | `:875-934` |
| `2 <= p_filesz <= PATH_MAX` (4096) | ENOEXEC (pre) | `:890-892` |
| `p_filesz` bytes are read at `p_offset` from the file (not from memory); short read | error (pre) | `:899-902` |
| last byte (`[p_filesz-1]`) must be `'\0'` | ENOEXEC (pre) | `:904-906` |
| an earlier embedded NUL truncates the path (the buffer is passed as a C string) | uses the truncated path | `:908` (`open_exec`) |
| the path does not need to be in a PT_LOAD for the kernel (glibc ld.so, below, does need it mapped) | — | |
| `open_exec` fails | that error, e.g. ENOENT (pre) | `:908-911` |
| `p_vaddr`, `p_memsz`, `p_flags`, `p_align` | not used | |

### PT_GNU_STACK

| Rule | Consequence | Source |
|---|---|---|
| `p_flags & PF_X` -> executable stack, else non-executable. Every PT_GNU_STACK is visited; the **last** one wins. Other fields (size, offset) are ignored. | used | `:940-948` |
| absent -> `EXSTACK_DEFAULT`. x86-64: `READ_IMPLIES_EXEC` only for ia32 processes (`elf_read_implies_exec`); arm64 native: generic `elf_read_implies_exec` = 0. | used | `arch/x86/include/asm/elf.h:286-287`; `include/linux/elf.h:9-14` |

### PT_GNU_PROPERTY

| Rule | Consequence | Source |
|---|---|---|
| Parsed only if the arch selects `CONFIG_ARCH_USE_GNU_PROPERTY`: arm64 does (`arch/arm64/Kconfig:93`), x86 does **not** in v7.0.12. | x86-64: ignored entirely | `parse_elf_properties:788-789` |
| If there is an interpreter, only the **interpreter's** PT_GNU_PROPERTY is parsed; the program's is ignored by the kernel (`elf_property_phdata = NULL` before scanning the interpreter). Otherwise the program's. Last PT_GNU_PROPERTY in table wins. | — | `:878-881`, `:976-982`, `:994` |
| `p_filesz <= 1024` | ENOEXEC (pre) | `:798-799` |
| note header readable and `>= 12 + 4` bytes | EIO (pre) | `:802-806` |
| `n_type == NT_GNU_PROPERTY_TYPE_0`, `n_namesz == 4`, name `"GNU"` | ENOEXEC (pre) | `:808-812` |
| `n_descsz` fits in the bytes read | ENOEXEC (pre) | `:814-820` |
| each property: header fits, `pr_datasz` fits, rounded size fits; `pr_type` strictly ascending (no duplicates) | ENOEXEC (pre) | `parse_elf_property:729-773` |
| arm64 `GNU_PROPERTY_AARCH64_FEATURE_1_AND`: `pr_datasz == 4` | ENOEXEC (pre). BTI bit enables BTI if the CPU supports it. | `arch/arm64/include/asm/elf.h:260-280` |

This is the only place where the kernel is *stricter* than ld.so: glibc
silently skips malformed property notes (below).

### Others

| Type | Kernel | Source |
|---|---|---|
| `PT_DYNAMIC` | ignored | grep |
| `PT_TLS` | ignored | grep |
| `PT_PHDR` | ignored | grep |
| `PT_NOTE` (other than GNU property) | ignored | grep |
| unknown `p_type` | ignored | the loops only `switch` on known values |
| `PT_LOPROC..PT_HIPROC` | passed to `arch_elf_pt_proc`; no-op on arm64 and x86 | `:949-954` |

## 3. glibc ld.so (2.44)

glibc applies two very different levels of checking:

* The **main program when started by the kernel** (the normal case): ld.so
  never re-reads or re-validates its ELF header. It uses only the auxiliary
  vector `AT_PHDR`/`AT_PHNUM`/`AT_ENTRY` (`sysdeps/unix/sysv/linux/dl-sysdep.c:93`,
  `elf/rtld.c:1642-1644`) and walks the in-memory program headers.
* **Shared libraries** (`DT_NEEDED`, `dlopen`) and a program started as
  `ld.so ./prog`: these go through `open_verify` and
  `_dl_map_object_from_fd`, which are strict about the header.

### 3a. Main program (kernel-loaded), `elf/rtld.c:rtld_setup_main_map:1085-1229`

| Item | Behaviour | Source |
|---|---|---|
| ELF header | not read | — |
| `PT_PHDR` | `l_addr = AT_PHDR - PT_PHDR.p_vaddr`. If absent, `l_addr` stays 0, which is right for ET_EXEC but wrong for a PIE. The phdrs are scanned **in table order** and `l_addr` is used immediately by `PT_DYNAMIC` and `PT_INTERP`, so `PT_PHDR` must come before them. | `:1120-1123` |
| `PT_DYNAMIC` | `l_ld = l_addr + p_vaddr` (read from memory, so it must be inside a mapped PT_LOAD) | `:1124-1128` |
| `PT_INTERP` | the string at `l_addr + p_vaddr` is read from **memory** (must be mapped), recorded as ld.so's name | `:1130-1142` |
| `PT_LOAD` | only used to compute `l_map_start`/`l_map_end`; unordered segments are tolerated (comment at `:1101-1112` says so explicitly) | `:1144-1169` |
| `PT_TLS` | `p_memsz > 0` -> TLS block of the main program | `:1171-1196` |
| `PT_GNU_STACK` | sets `dl_stack_prot_flags`; last wins | `:1198-1200` |
| `PT_GNU_RELRO` | recorded | `:1202-1205` |

### 3b. Libraries: `elf/dl-load.c:open_verify:1566-1750`

| Field | Condition | Error string | Line |
|---|---|---|---|
| file length | `>= sizeof(Ehdr)` | "file too short" | 1641-1648 |
| `e_ident[0..EI_ABIVERSION]` | equals `{7f 'E' 'L' 'F', native class, native data, EV_CURRENT, ELFOSABI_SYSV}` or the same with `ELFOSABI_GNU` | "invalid ELF header" / "ELF file data encoding not little-endian" / "ELF file version ident does not match current one" / "ELF file OS ABI invalid" | 1658-1708; `sysdeps/gnu/ldsodefs.h:27-44` |
| `EI_ABIVERSION` | 0, or `< LIBC_ABI_MAX` when OSABI is GNU | "ELF file ABI version invalid" | 1709-1711 |
| `e_ident[EI_PAD..16]` | all zero | "nonzero padding in e_ident" | 1712-1714 |
| `EI_CLASS` mismatch | not fatal: the file is skipped (`ENOENT`) and the search continues for a file of the right class | — | 1683-1694 |
| `e_version` | `== EV_CURRENT` | "ELF file version does not match current one" | 1722-1726 |
| `e_machine` | `elf_machine_matches_host` (aarch64: `EM_AARCH64`, x86-64: `EM_X86_64`) | silently skipped, search continues (`ENOENT`) | 1727-1734; `sysdeps/aarch64/dl-machine.h:37-40`, `sysdeps/x86_64/dl-machine.h:44-47` |
| `e_type` | `ET_DYN` or `ET_EXEC` | "only ET_DYN and ET_EXEC can be loaded" | 1735-1739 |
| `e_phentsize` | `== sizeof(Phdr)` | "ELF file's phentsize not the expected size" | 1741-1745 |
| `e_shoff`/`e_shnum`/`e_shstrndx`/`e_ehsize`/`e_flags` | not checked | — | grep: no `e_sh`/`Shdr` in `elf/dl-load.c`, `elf/rtld.c`, `elf/dl-*.h` |

### 3c. Libraries: program headers, `_dl_map_object_scan_phdrs:985-1110` and `_dl_map_segments` (`elf/dl-map-segments.h`)

| Item | Rule | Consequence | Source |
|---|---|---|---|
| phdr table readable | `pread` of each chunk succeeds | "cannot read file data" | `dl-load.c:997-1002` |
| PT_LOAD `p_offset`/`p_vaddr` | `(p_vaddr - p_offset) % pagesize == 0` | "ELF load command address/offset not page-aligned" | `dl-load.c:1009-1014` |
| PT_LOAD count | `>= 1` | "object file has no loadable segments" | `dl-load.c:1276-1280` |
| PT_LOAD order | **assumed ascending, not checked**: the mapping length is `last.p_vaddr+p_memsz - first.mapstart` using table order. With holes, `last_mapstart < first.mapend` is rejected. | "ELF load command address/offset not page-aligned" (holes case) | `dl-load.c:1027-1033`, `1306`; `dl-map-segments.h:112-121` |
| PT_LOAD `p_align` | largest power of two is used for the base alignment; others ignored | — | `dl-load.c:1020-1021` |
| `p_filesz > p_memsz` | **not checked** (no zero fill happens) | accepted | `dl-map-segments.h:152` |
| `e_type` for dlopen | ET_EXEC cannot be dlopen'ed | "cannot dynamically load executable" | `dl-load.c:1286-1293` |
| PT_DYNAMIC | ET_DYN without PT_DYNAMIC, or any PT_DYNAMIC with `p_filesz == 0` | "object file has no dynamic section" | `dl-load.c:1040-1052`, `1296-1300` |
| PT_PHDR | gives `l_phdr`; else the PT_LOAD containing the **whole** phdr table (`mapoff <= e_phoff` and table end within the file-backed part); else the table is copied from the file into malloc'd memory | accepted in all cases | `dl-load.c:1054-1056`, `1339-1361`; `dl-load.h:209-221` |
| PT_TLS | `p_memsz == 0` ignored; `p_align == 0` allowed | — | `dl-load.c:1058-1088` |
| PT_GNU_STACK | if it asks for an executable stack and the stack is not executable: allowed at startup only with tunable `glibc.rtld.execstack=1`, else rejected | "cannot enable executable stack as shared object requires" | `dl-load.c:1090-1092`, `1363-1380` |
| PT_GNU_PROPERTY | read from memory; skipped silently if `p_align != 8` (ELF64) / 4 (ELF32), if `n_descsz < 8` or misaligned, if types are not ascending, or if a property overruns the note | ignored on any error (never fatal) | `dl-load.c:_dl_process_pt_gnu_property:853-913` |
| arch hook | `elf_machine_reject_phdr_p` | "ELF file incompatible with this system" | `dl-load.c:1103-1107` |

### 3d. What glibc needs from PT_DYNAMIC (section headers are never used)

Parsing: `elf/get-dynamic-info.h:elf_get_dynamic_info`. Entries are read up to
the first `DT_NULL` (not bounded by `p_memsz`); each known tag is stored in
`l_info[]`, so for duplicate tags the **last** entry wins. Unknown tags are
skipped.

| Tag | Use | Required? | Source |
|---|---|---|---|
| `DT_STRTAB` | base for every string: `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`/`DT_RUNPATH`, symbol names | needed as soon as there is any `DT_NEEDED`/symbol; not validated, a missing one dereferences null | `elf/dl-deps.c:197-227`, `elf/dl-lookup.c:401-402` |
| `DT_SYMTAB` | symbol table base; its length is **not** stored anywhere in the dynamic section and is derived from the hash table | needed for symbol lookup | `elf/dl-lookup.c:401` |
| `DT_GNU_HASH` | preferred if present; bloom `bitmask_nwords` must be a power of two (`assert`) | one of `DT_GNU_HASH`/`DT_HASH` is needed for lookups in that object; with neither, `_dl_setup_hash` returns and the object exports nothing | `elf/dl-setup_hash.c:24-61` |
| `DT_HASH` | used only if there is no `DT_GNU_HASH`; `nchain` = number of symbols | see above | `elf/dl-setup_hash.c:53-61` |
| `DT_NEEDED` | `strtab + d_val` is the library name; processed in dynamic-section order | — | `elf/dl-deps.c:211-227` |
| `DT_RELA`+`DT_RELAENT` | if `DT_RELA` is present, `DT_RELAENT` must equal `sizeof(Rela)` (`assert`) | — | `get-dynamic-info.h` (RELAENT assert) |
| `DT_PLTREL` | must be `DT_REL` or `DT_RELA` (`assert`) | — | same |
| `DT_RELR`+`DT_RELRENT` | `DT_RELRENT == sizeof(Relr)` (`assert`) | — | same |
| `DT_STRSZ`, `DT_SYMENT` | not used for bounds checking in the paths read | — | not found in the files read; not verified elsewhere |

## 4. musl ldso (1.2.6)

### 4a. Main program (kernel-loaded), `ldso/dynlink.c:__dls3:1832-1859`

| Item | Behaviour | Source |
|---|---|---|
| ELF header | not read | — |
| `PT_PHDR` | `base = AT_PHDR - p_vaddr`; absent -> base 0 (breaks PIE) | `:1840-1841` |
| `PT_INTERP` | `p_vaddr` recorded as ld.so's name (read from memory) | `:1842-1843`, `:1853` |
| `PT_TLS` | recorded | `:1844-1849` |
| `PT_DYNAMIC`, `PT_GNU_RELRO`, `PT_GNU_STACK`, `PT_LOAD` | read by `kernel_mapped_dso` | `:1437-1465` |
| stride | `AT_PHENT` | `:1839` |

### 4b. Libraries, `ldso/dynlink.c:map_library:685-869`

musl is the most permissive of the three. It does **not** check the magic,
`EI_CLASS`, `EI_DATA`, `EI_VERSION`, `EI_OSABI`, padding, `e_version` or
`e_machine` anywhere in `ldso/dynlink.c` (grep for `ELFMAG`, `e_ident`,
`EI_`, `e_machine`, `e_version`: no hits).

| Item | Rule | Consequence | Source |
|---|---|---|---|
| file length | `>= sizeof(Ehdr)` | ENOEXEC | `:704-705` |
| `e_type` | `ET_DYN` or `ET_EXEC` | ENOEXEC | `:705` |
| `e_phentsize` | **not compared** with `sizeof(Phdr)`; used as the stride (`phsize = e_phentsize * e_phnum`) | wrong values just misparse | `:707`, `:723` |
| phdr table | must be fully readable | ENOEXEC | `:708-722` |
| PT_LOAD order | not required; min/max over all PT_LOADs | accepted | `:741-752` |
| PT_DYNAMIC | required, and its `p_vaddr` must be non-zero (`if (!dyn) goto noexec`) | ENOEXEC | `:724-725`, `:754` |
| ET_EXEC not at its fixed address | `EBUSY` | error | `:813-816` |
| phdr address for `dl_iterate_phdr` | the first PT_LOAD whose file range contains the whole table; else none | — | `:825-831` |

### 4c. PT_DYNAMIC (`decode_dyn:974-992`, `decode_vec:218-227`)

For tags `< 32`, the **last** duplicate wins (`decode_vec`). `DT_GNU_HASH` and
`DT_VERSYM` are found with `search_vec`, i.e. the **first** one. `DT_SYMTAB`
and `DT_STRTAB` are taken unconditionally (missing -> base address). `DT_HASH`
is used for `count_syms` when present, else the symbol count is derived by
walking the `DT_GNU_HASH` chains (`count_syms:994-1011`).

## 5. Summary for a tolerant ELF reader

Fields that the kernel ignores (so a tolerant reader must **not** reject a
file because of them; report a warning instead):

| Field | Kernel | glibc (library) | musl (library) |
|---|---|---|---|
| `EI_CLASS` | ignored (handler decides layout) | checked | ignored |
| `EI_DATA` | ignored (host order assumed) | checked | ignored |
| `EI_VERSION` | ignored | checked | ignored |
| `EI_OSABI` | ignored | SYSV or GNU | ignored |
| `EI_ABIVERSION` | ignored | 0 (or GNU < max) | ignored |
| `e_ident[9..16]` padding | ignored | must be 0 | ignored |
| `e_version` | ignored | must be 1 | ignored |
| `e_flags` | ignored (native) | ignored | ignored |
| `e_ehsize` | ignored | ignored | ignored |
| `e_shoff`/`e_shentsize`/`e_shnum`/`e_shstrndx` | never read | never read | never read |
| `PT_PHDR` | ignored | used for load bias | used for load bias |
| `PT_DYNAMIC`, `PT_TLS`, `PT_NOTE`, unknown types | ignored | used | used |
| PT_LOAD order and overlap | not checked | order assumed, not checked | not required |
| `p_align` (non power of two, or `p_offset%p_align != p_vaddr%p_align`) | ignored | ignored | ignored |

Fields the kernel does enforce (a reader may treat violations as "this would
not execute", still without refusing to show the rest):

* magic `\x7fELF`;
* `e_type` in {`ET_EXEC`, `ET_DYN`};
* `e_machine` accepted by the arch;
* `e_phentsize == sizeof(Phdr)`;
* `1 <= e_phnum` and `e_phnum * e_phentsize <= 65536`, table readable at `e_phoff`;
* PT_INTERP: `2 <= p_filesz <= 4096`, last byte NUL, path openable;
* PT_LOAD: `p_offset ≡ p_vaddr (mod page)` when `p_filesz > 0`,
  `p_filesz <= p_memsz`, addresses below `TASK_SIZE` (post-commit, SIGSEGV);
* arm64 only, and only for the object whose PT_GNU_PROPERTY is parsed: a
  well-formed `NT_GNU_PROPERTY_TYPE_0` note `<= 1024` bytes with ascending types.

Consequences for `unforge-elf`:

1. Never require section headers. A complete view of a dynamically linked
   file is reachable from `PT_LOAD` + `PT_DYNAMIC` alone (`DT_STRTAB`,
   `DT_SYMTAB`, `DT_GNU_HASH`/`DT_HASH` for the symbol count, `DT_NEEDED`,
   relocation tables), mapped from virtual address to file offset through the
   PT_LOADs.
2. Read `EI_CLASS`/`EI_DATA` as the *claimed* layout but be ready for a file
   whose claim disagrees with what the kernel would do (e.g. a lying
   `EI_CLASS`); the kernel's choice is driven by `e_machine` and the handler.
3. Unordered or overlapping PT_LOADs, odd `p_align`, and `e_phoff` outside any
   PT_LOAD are all executable; they are warnings, not errors.
4. "Duplicate wins" differs per consumer: kernel uses the first PT_INTERP and
   the last PT_GNU_STACK; glibc and musl use the last duplicate dynamic tag
   (musl: first for `DT_GNU_HASH`/`DT_VERSYM`). A reader should keep all
   duplicates and flag them.

## Not verified

* Exact runtime behaviour when a PT_LOAD's file range extends past EOF
  (SIGBUS on touch vs `-EFAULT` from `padzero`) was reasoned from source only.
* Behaviour of the compat (32-bit) handler on the linuxkit kernel depends on
  `CONFIG_COMPAT` and on whether the CPU supports AArch32 EL0; neither was
  checked.
* The page size of the linuxkit arm64 kernel was not read from its config.
* glibc's handling of a missing `DT_STRTAB`/`DT_SYMTAB` was inferred from the
  absence of a check in the files read; other glibc files may add checks.

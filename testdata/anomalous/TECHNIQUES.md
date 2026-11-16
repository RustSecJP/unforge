# Malformed-but-executable ELF: a technique catalogue

This file lists ELF tricks that break or mislead analysis tools while the file
still runs. Malware uses them, and so does "tiny ELF" size golfing. For each
technique it records:

- what is changed,
- why tools break,
- whether Linux still loads the file (from kernel source and from a real run),
- how to build it from a normal binary, in a way you can repeat,
- what a **tolerant** reader should still extract, and what it should report
  as a diagnostic.

The design question behind it: the reference for what an executable *is* is
how the Linux kernel ELF loader (`fs/binfmt_elf.c`) and the dynamic linker
(glibc `ld.so`, musl `ldso`) treat it. Another parser such as `object` or
binutils is not that reference. A reader that rejects what the kernel runs is
blind to exactly the files an analyst most needs to see.

Status labels used below:

- **[source]**: checked by reading the cited source at the cited version.
- **[run]**: observed by running the file under the real Linux kernel (setup
  below).
- **[cited]**: taken from a published source that I did not reproduce.
- **[NOT VERIFIED]**: plausible, but not checked in source or by a run.

---

## 0. How the verdicts were produced

### 0.1 Execution setup

| item | value |
|---|---|
| Host | macOS on aarch64, Docker Desktop |
| Kernel | `7.0.12-linuxkit`, aarch64 (`uname -mr` inside the container) |
| Container image | `debian:bookworm-slim`, platform `linux/arm64`, digest `sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc`, with `binutils` 2.40 installed from Debian |
| Dynamic loader | Debian glibc 2.36-9+deb12u14 (`ld-linux-aarch64.so.1`) |
| Runner | a static aarch64 musl program that starts each file with `std::process::Command`. A missing image or a kernel refusal is reported as an `exec` error such as `Exec format error (os error 8)`, never as a shell fallback. (`sh` and glibc `execvp` re-run an `ENOEXEC` file as a shell script, which hides the kernel verdict.) |

**Which loader produced the verdict.** Every file below is an aarch64 ELF run
in a `linux/arm64` container, so the real kernel `binfmt_elf` handled it. There
is one exception (see T19): Docker Desktop registers `binfmt_misc` handlers that
send x86-64, i386, arm (32-bit), mips64, ppc64le, riscv64 and s390x ELF files to
`qemu-*` or Rosetta. I listed them by mounting `binfmt_misc` in a privileged
container. Each entry matches on a magic and mask that cover `EI_CLASS`,
`EI_DATA`, `e_type` and `e_machine`. Example, the x86-64 entry:

```
interpreter /usr/bin/qemu-x86_64          (also /run/rosetta/rosetta)
magic 7f454c4602010100000000000000000002003e00
mask  fffffffffffefe00fffffffffffffffffeffffff
```

So for a non-aarch64 ELF in this setup, the verdict comes from an **emulator's
ELF loader, not from the kernel**. Two consequences:

1. Never record a verdict from a `linux/amd64` container as "kernel".
2. Under such an emulator, corrupting `EI_CLASS` or `EI_DATA` stops the
   `binfmt_misc` magic from matching. The file then fails with `ENOEXEC`,
   although a native x86-64 kernel would load it (it ignores those bytes, see
   §1). An emulated run can therefore be *stricter* than the kernel.

### 0.2 Base binaries

| name | what | sha256 |
|---|---|---|
| `static-musl` | `testdata/bin/aarch64-unknown-linux-musl/panics-O3-strip-symbols` (static, `ET_EXEC`, no `.symtab`, 19 sections, 9 program headers) | `de69c519622d4e32a5edf7c1a5b1cad1652e53406e5b1152fcba974e3cf51872` |
| `static-musl-syms` | `testdata/bin/aarch64-unknown-linux-musl/panics-O0` (has `.symtab`, 4117 symbols) | `206df41cf8a1815225e73f50001bb41d5bd2f17157ee6bd3fb33e16478fcda78` |
| `true-glibc` | `/bin/true` from the image above (coreutils 9.1-1, glibc PIE, `ET_DYN`, has `PT_INTERP` and `PT_DYNAMIC`) | `dfd1b0241759344063bd5052622d90910c53084234a26f19527d150da3e43d4b` |

The `testdata/bin` hashes hold for the build recorded in
`testdata/bin/MANIFEST.txt` on 2026-11-16 (rustc 1.99.0). After a rebuild they
may change. Every variant is made by the generator in the appendix
(`python3 -I mutate.py <bases-dir> <out-dir>`). It changes fixed fields only, so
the same base always gives the same output bytes. Variant names below
(`s05-…`, `d40-…`, `t60-…`) are that script's file names: `s` = from
`static-musl`, `d` = from `true-glibc`, `y` = from `static-musl-syms`,
`t` = built by hand from nothing.

### 0.3 Tools compared

- GNU `readelf -a -W`, `objdump -d`, `nm` (binutils 2.40, Debian bookworm, aarch64).
- `unforge elf <file>`: the CLI built from this working tree on 2026-11-16, so
  the results show where the current reader stands.

The full results table is in §4.

---

## 1. What the loaders actually read (the ground truth)

`LOADER_RULES.md` in this directory has the full field-by-field reference,
written against the exact v7.0.12 stable tree. This section is the short form
that the techniques below rely on. If the two documents disagree, re-check
against source; `LOADER_RULES.md` cites the more exact tree.

### 1.1 Linux kernel, `fs/binfmt_elf.c`, `load_elf_binary()` (tag v7.0) [source]

The running kernel is 7.0.12. The source read is the v7.0 tag. I did not diff
the stable 7.0.y patches; the [run] results agree with v7.0 on every point
below.

| field / structure | kernel use | where |
|---|---|---|
| `e_ident[0..4]` | must equal `\x7fELF` | `memcmp(elf_ex->e_ident, ELFMAG, SELFMAG)` at the top of `load_elf_binary` |
| `e_ident[EI_CLASS]`, `[EI_DATA]`, `[EI_VERSION]`, `[EI_OSABI]`, `[EI_ABIVERSION]`, `EI_PAD` | **never read** by the loader. The only matches for `EI_*` in the file are in the core-dump writer (`fill_elf_header`) | grep of `binfmt_elf.c` |
| `e_type` | must be `ET_EXEC` or `ET_DYN` | `load_elf_binary` |
| `e_machine` | `elf_check_arch()`. arm64: `(x)->e_machine == EM_AARCH64` (`arch/arm64/include/asm/elf.h`). x86-64: `(x)->e_machine == EM_X86_64` (`arch/x86/include/asm/elf.h`) | |
| `e_version`, `e_flags`, `e_ehsize` | not read (some architectures read `e_flags` through `arch_check_elf` / `elf_check_arch`; [NOT VERIFIED] per architecture) | |
| `e_shoff`, `e_shentsize`, `e_shnum`, `e_shstrndx` | **never read** by the loader (they appear only in the core-dump writer) | grep |
| `e_phentsize` | must equal `sizeof(struct elf_phdr)`, else `ENOEXEC` | `load_elf_phdrs()` |
| `e_phnum` | `sizeof(phdr) * e_phnum` must be non-zero and `<= 65536`. For ELF64 that is at most 1170 entries. `PN_XNUM` (0xffff) is not honoured when loading, so 0xffff fails this check | `load_elf_phdrs()` |
| `e_phoff` | the whole table must be readable from the file (`elf_read` demands exactly `size` bytes) | `load_elf_phdrs()` |
| `e_entry` | used as given (plus `load_bias` for `ET_DYN`). It is not checked against any segment | |
| `PT_INTERP` | `p_filesz` in `[2, PATH_MAX]`, bytes read from **`p_offset`**, last byte must be NUL | `load_elf_binary` |
| `PT_GNU_STACK` | `p_flags` sets whether the stack is executable | |
| `PT_GNU_PROPERTY` | parsed (`parse_elf_properties`), `p_filesz` limited | |
| `PT_LOAD` | for each, in table order: `elf_load()` maps `p_filesz` bytes from `p_offset` at `p_vaddr`. The first `PT_LOAD` of an `ET_EXEC` uses `MAP_FIXED_NOREPLACE`; every later one uses **`MAP_FIXED`**, so a later overlapping segment replaces an earlier one. The load is refused if `p_filesz > p_memsz`, `p_memsz > TASK_SIZE` or `TASK_SIZE - p_memsz < p_vaddr` | `load_elf_binary` |
| `p_align` | used only for the `ET_DYN` base. Values that are not a power of two are skipped (`maximum_alignment()`) | |
| program header table address (`AT_PHDR`) | `phdr_addr` is set only when some `PT_LOAD` covers `e_phoff` in the file. Otherwise `AT_PHDR` stays `0 + load_bias` | the `p_offset <= e_phoff < p_offset + p_filesz` test in the `PT_LOAD` loop, and `NEW_AUX_ENT(AT_PHDR, phdr_addr)` |
| `PT_PHDR`, `PT_DYNAMIC`, `PT_NOTE`, `PT_TLS`, `PT_GNU_EH_FRAME`, `PT_GNU_RELRO` | **not read** by the kernel. They are for user space | grep |
| bytes past EOF | `vm_mmap` of a file range past EOF succeeds. Touching a page that lies wholly past EOF raises `SIGBUS`. For a segment with `p_memsz > p_filesz`, `padzero()` writes zeros to the tail of the last file page. If that fails and the segment is writable, `elf_load` returns `-EFAULT` | `elf_load()`, `padzero()` |
| failure after the point of no return | `exec` kills the task with `SIGSEGV` before any user instruction runs | `fs/exec.c` v7.0, `force_fatal_sig(SIGSEGV)` when `bprm->point_of_no_return` |

On 64-bit kernels, the compat loader (`compat_binfmt_elf`) checks
`compat_elf_check_arch()`. That is `EM_ARM` on arm64, and `EM_386` (or
`EM_X86_64` for x32) on x86-64. On arm64 a file with `e_machine == EM_AARCH64`
therefore always goes to the native 64-bit loader, whatever `EI_CLASS` says.
That loader reads the bytes as `Elf64_Ehdr`. **On x86-64 with
`CONFIG_X86_X32_ABI`, an `EM_X86_64` file with `EI_CLASS=1` could be claimed by
the compat (x32) loader, depending on the order the handlers were registered.
[NOT VERIFIED]**

### 1.2 glibc `ld.so` for the main program (glibc 2.44 source; Debian 2.36 was run) [source]

- `open_verify()` (`elf/dl-load.c`) strictly checks `EI_CLASS`, `EI_DATA`,
  `EI_VERSION`, `EI_OSABI`/`EI_ABIVERSION`, `EI_PAD`, `e_version`,
  `e_phentsize` and `e_type`. It runs only for objects that `ld.so` opens
  itself: `DT_NEEDED` libraries, `dlopen`, and a program started as
  `ld.so ./prog` (`_dl_map_object(NULL, rtld_progname, lt_executable, …)` in
  `elf/rtld.c`).
- A main program that the **kernel** loaded is not re-verified. `rtld.c` takes
  `AT_PHDR`/`AT_PHNUM` from the aux vector and scans the program headers.
  `PT_PHDR` sets `l_addr = phdr - p_vaddr`, and **`PT_DYNAMIC` sets
  `l_ld = l_addr + p_vaddr`**. Only `p_vaddr` is used; `p_offset` and
  `p_filesz` of `PT_DYNAMIC` are ignored. [source], confirmed by [run] d40.
- So `EI_*` garbage in a dynamically linked **main program** still runs ([run]
  d16–d21). The same garbage in a **shared library** makes `ld.so` refuse it
  ("ELF file data encoding not little-endian", "wrong ELF class", …).
  [source; the library case was not run]

### 1.3 musl (v1.2.6 source) [source]

- Static programs: `static_init_tls()` (`src/env/__init_tls.c`) walks
  `AT_PHDR`/`AT_PHNUM` to find `PT_PHDR`, `PT_TLS` and `PT_GNU_STACK`. If
  `AT_PHDR` is wrong, a static musl program faults before `main` ([run] s24).
- Static PIE and the dynamic linker: `_dlstart_c()` (`ldso/dlstart.c`) gets
  `dynv` from the `_DYNAMIC` address the start code computed, and falls back to
  scanning for `PT_DYNAMIC` only when it is started as the loader itself. So for
  musl static PIE, editing the `PT_DYNAMIC` program header is likely not
  noticed at run time. [source, NOT run: the corpus has no musl static PIE]

### 1.4 What this means for a reader

The kernel's view of a runnable file is:

> the 4-byte magic, `e_type`, `e_machine`, `e_entry`, `e_phoff`,
> `e_phentsize`, `e_phnum`, and the program header table, then the bytes the
> `PT_LOAD` entries map.

The user-space loader adds `PT_INTERP`, `PT_DYNAMIC` (through `p_vaddr`, in
memory) and `PT_TLS`. **Nothing in the section header table, and nothing in
`e_ident` after the magic, affects whether the file runs.** Every technique
below abuses that gap. The same field list appears in the Teensy article and in
the Cozzi et al. study.

---

## 2. A tolerant reader in one page

These are the expected behaviours used in every "tolerant reader" entry below.

1. **Two views.** Build the *loader view* (header subset + program headers + a
   map of memory from virtual address to file bytes) first. Build the *linker
   view* (sections, symbols, string tables) second, and treat it as unchecked
   claims about the loader view. A broken linker view must never stop the
   loader view from being produced.
2. **No fatal error except for the loader-view minimum.** Stop only when the
   magic is wrong or no program header table can be read at all, and even then
   give back the ELF header fields. Everything else is a diagnostic attached
   to the result, with a severity and the byte range involved.
3. **Report the kernel's verdict as a diagnostic, not as the rule for
   parsing.** For example: "the kernel would refuse this: `e_phentsize` 32 ≠ 56
   (`ENOEXEC`)". Still parse what can be parsed.
4. **Decide the layout as the loader does.** For a known `e_machine`, use the
   layout that machine requires (ELF64 for `EM_AARCH64`, `EM_X86_64`,
   `EM_PPC64`, `EM_S390`, …). Check byte order by testing which order makes
   `e_machine` a machine the reader supports. Report any disagreement with
   `EI_CLASS`/`EI_DATA`. If `e_machine` is unknown, fall back to `EI_*`, and
   if those are invalid, report "layout undetermined". See T12 for why this is
   a heuristic and where it can be wrong.
5. **Clip, don't trust.** Every size and offset is checked against the file
   length with overflow-checked arithmetic. A section whose range runs past EOF
   is kept with its claimed values plus a "clipped to N bytes" or "no file
   bytes" diagnostic. It is not dropped.
6. **Views, not copies.** Tables are zero-copy views over the input with
   lazily decoded entries, so N headers that point at the same bytes cost O(N)
   headers, not O(N × table size) memory (see T08).
7. **Bounded work and bounded output.** Cap the number of diagnostics per kind
   (binutils `readelf` printed 3,236,000 warning lines, 28 million lines in
   total, for one 526 KB file, T08). Never loop over a count that has not been
   checked against the bytes that exist.
8. **Cross-check the views.** Mismatches between sections and segments, names
   and contents, or `e_entry` and executable memory are findings in their own
   right, so report them.

---

## 3. Catalogue

Each entry has: **Changed**, **Why tools break**, **Kernel verdict**, **Build**,
**Tolerant reader**. "Observed" lines quote the §4 runs.

### T01. Section header table removed (`e_shoff = 0`, `e_shnum = 0`, `e_shstrndx = 0`)

- **Changed.** The three section-table fields in the ELF header are zeroed.
  Two forms:
  - *zeroed*: the table bytes stay in the file;
  - *sstrip*: the file is also cut after the last byte any program header
    refers to. ELFkickers `sstrip` does exactly this: `getmemorysize()` takes
    `max(e_phoff + e_phnum*sizeof(phdr), e_ehsize, p_offset + p_filesz for each
    non-PT_NULL)`, and `modifyheaders()` zeroes `e_shoff`/`e_shnum`/`e_shstrndx`
    if `e_shoff >= newsize` and clips any `p_filesz` that runs past the new
    size. [source: `sstrip/sstrip.c`, BR903/ELFkickers master]
- **This is valid ELF.** gABI: "If the file has no section header table, this
  member holds zero" (`e_shoff`). Cozzi et al. found "removing all information
  about the ELF sections" in about 5% of 10,548 Linux malware samples
  ("Anomalous ELF"). [cited]
- **Why tools break.** Tools that find code or symbols through sections
  (`.text`, `.symtab`, `.dynsym`) see nothing. Observed: `objdump -d` exits 0
  and prints 3 lines (no disassembly at all). `nm` prints "no symbols", even for
  the dynamic `true` whose `.dynsym` is still in memory through `PT_DYNAMIC`.
  Cozzi et al. report pyelftools and GDB trouble with stripped or corrupt
  section tables (Table III). [cited]
- **Kernel verdict.** Runs: s01, s02, d01, d02 all exit 0 [run]. The kernel
  never reads these fields [source].
- **Build.** Write 0 to `e_shoff` (offset 0x28, 8 bytes in ELF64), `e_shnum`
  (0x3c, 2 bytes) and `e_shstrndx` (0x3e, 2 bytes). For the sstrip form, also
  cut the file to the size computed above.
- **Tolerant reader.** Extract the header, program headers, the memory map,
  `PT_INTERP`, and, through `PT_DYNAMIC` → `DT_SYMTAB`/`DT_STRTAB`/`DT_HASH` or
  `DT_GNU_HASH`/`DT_RELA*`/`DT_JMPREL`, the dynamic symbols and relocations,
  all by translating virtual addresses through the `PT_LOAD` map.
  `PT_GNU_EH_FRAME` gives `.eh_frame_hdr`, so function starts can still be
  found. Diagnostic: *info* "no section header table" (normal after `sstrip`,
  unusual from a compiler). Not an error.

### T02. Garbage `e_shoff`

- **Changed.** `e_shoff` points past EOF (`s04`: `filesize + 0x1000`) or is a
  huge value (`s03`, `d03`: `0xdeadbeefdeadbeef`). Cozzi Table II: "Section
  header table pointing beyond file data", 178 samples (1.69%). [cited]
- **Why tools break.** Observed: `objdump`/`nm` stop with "file format not
  recognized" (exit 1). `readelf` prints "Reading 1216 bytes extends past end of
  file for section headers" and continues with the header and segments. Cozzi:
  GDB "not being able to recognize the ELF binary and … unable to start the
  program". [cited]
- **Kernel verdict.** Runs (s03, s04, d03) [run]. Not read [source].
- **Build.** Overwrite the 8 bytes at 0x28.
- **Tolerant reader.** Same output as T01. Diagnostic: *warning* "section header
  table at 0x… (+0x… bytes) lies outside the file (N bytes); sections ignored".
  Use checked add (`e_shoff + e_shnum*e_shentsize` overflows for `0xdead…`).

### T03. Garbage `e_shnum`

- **Changed.** `e_shnum = 0xffff` (s05), so the table runs past EOF. Related:
  the tiny ELF (T10) has `e_shnum = 5` with `e_shoff = 0`, because the field
  overlaps `p_flags`.
- **Why tools break.** Observed: `objdump`/`nm` "file format not recognized".
  `readelf` "Reading 4194240 bytes extends past end of file". On t60 `readelf`
  says "Section headers are not available!". Tools that allocate
  `e_shnum * e_shentsize` up front can be made to allocate a lot. The binutils
  bugzilla has fuzz-found `readelf` crashes on crafted section tables, e.g.
  bugs 21135, 21142, 22552 and 33697. [cited from search results; I did not
  open each report, NOT VERIFIED in detail]
- **Kernel verdict.** Runs (s05, t60) [run].
- **Build.** Write 0xffff at 0x3c. Note: `e_shnum = 0` with a non-zero
  `e_shoff` is the gABI escape for "count is in `shdr[0].sh_size`". A reader
  must use the escape only when `shdr[0]` is inside the file. A May 2023 binutils
  mailing-list report describes `readelf` applying it when no table exists.
  [cited, NOT VERIFIED]
- **Tolerant reader.** Parse the entries that fit completely in the file. Then
  report *warning* "e_shnum says 65535, only K entries fit before EOF; using K".
  An alternative is to drop the table and fall back to T01; either way, say
  which was done. For `e_shoff == 0 && e_shnum != 0`: *warning* "e_shnum=5 but
  no section header table (e_shoff=0)", and use no sections.

### T04. Garbage `e_shentsize`

- **Changed.** `e_shentsize = 1` (s06). gABI wants every entry to be
  `sizeof(Elf64_Shdr)`.
- **Why tools break.** Observed: `readelf` "The e_shentsize field in the ELF
  header is less than the size of an ELF section header" and no sections.
  `objdump`/`nm` "file format not recognized".
- **Kernel verdict.** Runs (s06) [run].
- **Build.** Write 1 at 0x3a (2 bytes).
- **Tolerant reader.** If `e_shentsize < sizeof(Shdr)`: *warning* and no
  sections (the entries cannot be decoded). If `e_shentsize > sizeof(Shdr)`:
  decode each entry from its prefix with a stride of `e_shentsize`, and report
  *warning* "non-standard e_shentsize". Larger strides are what a future ABI
  extension would look like; [NOT VERIFIED] that any loader or linker accepts
  them.

### T05. Garbage `e_shstrndx`

- **Changed.** Out of range (s07: `0x1234`, 19 sections), or a valid index of a
  non-string section (s08: the index of `.text`, so names are read from code
  bytes). Cozzi Table II: "Wrong string table index (e_shstrndx)", 60 samples
  (0.57%). [cited]
- **Why tools break.** Observed: `objdump`/`nm` "has a corrupt string table
  index" but continue. `readelf` silently prints names as `<no-strings>` or as
  garbage. A tool that finds `.text` *by name* gets nothing, or finds the wrong
  bytes.
- **Kernel verdict.** Runs (s07, s08) [run].
- **Build.** Write the index at 0x3e.
- **Tolerant reader.** Keep all sections, with types, flags, addresses and
  ranges; names become "unknown". Diagnostic: *warning* "e_shstrndx 4660 out of
  range" or "e_shstrndx 5 is SHT_PROGBITS, not SHT_STRTAB; names are not
  trusted". Decode a name only when the referenced section is `SHT_STRTAB` and
  the string is NUL-terminated inside it. Never classify sections by name alone
  (see T07).

### T06. Lying section sizes and offsets

- **Changed.** `.text` `sh_size = 0xffffffffffff` (s09). `.rodata` `sh_offset`
  past EOF (s10). `.dynamic` header `sh_offset = 0xdeadbeef`,
  `sh_size = 0x7fffffff` (d42). `.interp` header `sh_offset` garbage (d45).
- **Why tools break.** Observed: `readelf` "Size of section 5 is larger than the
  entire file!". `objdump`/`nm` "has a section extending past end of file".
  Tools that copy a section's bytes or allocate `sh_size` can fail or run out
  of memory.
- **Kernel verdict.** Runs (s09, s10, d42, d45) [run]. The kernel reads
  `PT_INTERP` from the *program header's* `p_offset`. `ld.so` finds `.dynamic`
  through `PT_DYNAMIC.p_vaddr`. Neither reads the section header [source].
- **Build.** Rewrite `sh_size` (+0x20) or `sh_offset` (+0x18) in the section's
  64-byte header.
- **Tolerant reader.** Keep the section with the claimed values. Its byte view
  is the part inside the file (possibly empty). Diagnostic: *warning* "section
  [5] .text: size 0xffffffffffff exceeds the file; clipped to 0x…". For an
  `SHF_ALLOC` section, also check it against the segment that contains its
  `sh_addr` (T09). When a section header and its program header disagree
  (`.interp` vs `PT_INTERP`, `.dynamic` vs `PT_DYNAMIC`), the **program header
  wins** for "what runs". Report the disagreement.

### T07. Decoy sections: names or types disagree with contents

- **Changed.**
  - s11: the `sh_name` values of `.text` and `.rodata` are swapped, so the
    executable section is called `.rodata` and the data is called `.text`.
  - s12: `.text` is given `sh_type = SHT_NOBITS`.
  - d44: the `.dynsym` header is pointed at `.text` bytes.
- **Why tools break.** Observed:
  - s11: `objdump -d` disassembles by flag, so it prints "Disassembly of
    section .rodata:" with the real code under the wrong name. A tool that
    disassembles "`.text`" by name would decode the string data instead.
  - s12: `objdump -d` prints **19 lines** (only `.init`/`.fini`). The program's
    code is invisible because NOBITS sections "occupy no space in the file"
    (gABI).
  - d44: `readelf` prints 62 errors ("corrupt string table index") while
    decoding code as symbols.
  
  Published malware analyses describe these as anti-analysis tricks in general
  terms. I found no primary source for a specific family using the swap
  [NOT VERIFIED in the wild].
- **Kernel verdict.** Runs (s11, s12, d44) [run].
- **Build.** Swap the 4-byte `sh_name` fields of two headers. Write
  `SHT_NOBITS` (8) to `sh_type` (+0x04). Point `sh_offset` elsewhere.
- **Tolerant reader.** Classify memory by **segment flags** (`PF_X`), not by
  section names or types. Diagnostics:
  - *warning* "section `.rodata` is SHF_EXECINSTR / lies in an R-X segment";
  - *warning* "section `.text` is SHT_NOBITS but lies inside PT_LOAD file bytes
    [a, b)" (a NOBITS section with an `sh_addr` inside a segment's *file* part
    is suspicious);
  - for symbol tables: *warning* "`.dynsym` section disagrees with DT_SYMTAB
    0x…". Prefer the dynamic table that `PT_DYNAMIC` points to.

### T08. Overlapping sections

- **Changed.**
  - s13: every other `SHT_PROGBITS` section is made to cover exactly the bytes
    of `.text`.
  - s14: a new section header table at EOF, with the original 19 entries plus
    **2000 `SHT_SYMTAB` entries that all describe the same `.text` bytes**
    (`sh_entsize = 24`, `sh_link` = `.shstrtab`).
- **gABI.** "Sections in a file may not overlap. No byte in a file resides in
  more than one section." [source: gABI ch4.sheader] It is a rule for producers.
  Nothing at run time enforces it.
- **Why tools break.** Observed:
  - s13: `objdump -d` disassembles the same code three times (225k lines).
  - s14: `readelf -a -W` writes **28,240,081 lines (3,236,000 warnings)**.
    `objdump`/`nm` warn "multiple symbol tables detected" and use one table.
  - `unforge` refuses s14 ("symbol tables: 0x23c1cf00 bytes in total exceed the
    file (0x80800 bytes), so they overlap").
  
  That check stops the O(n²) memory use of an earlier design, where every table
  was copied into a widened `Vec`. It does so by rejecting input the kernel
  runs.
- **Kernel verdict.** Runs (s13, s14) [run].
- **Build.** See `overlap()` and `many_symtabs()` in the appendix.
- **Tolerant reader.** Accept the overlap. Report *warning* "sections [a] and
  [b] overlap in file range [x, y)" once per pair, or once per group with a
  count for large groups; cap the output. Use lazy views so that 2000 tables
  over the same bytes cost 2000 small headers, not 2000 decoded copies. A
  consumer that wants "the" symbol table should pick by rule (first
  `SHT_SYMTAB` whose `sh_link` is an `SHT_STRTAB`; this matches what binutils
  printed for s14 "ignoring the table in section 20", [NOT VERIFIED] as
  binutils' exact rule) and report the others as ignored.

### T09. Sections that do not match segments

- **Changed.** `sh_addr` of every allocated section is shifted by `+0x100000`
  (s15), so the section view says code is at addresses that no `PT_LOAD` maps.
  A variant (not built): `sh_offset` and `sh_addr` that are inconsistent with
  the containing segment's `p_vaddr - p_offset`.
- **Why tools break.** Tools that print symbols or cross-references from
  `sh_addr` give addresses that do not exist at run time. Debuggers set
  breakpoints in the wrong place. Observed: `readelf`/`objdump` give **no
  diagnostic at all** for s15. This is a silent mislead.
- **Kernel verdict.** Runs (s15) [run].
- **Build.** Add a constant to `sh_addr` (+0x10) of every header where it is
  non-zero.
- **Tolerant reader.** For each `SHF_ALLOC` section with file bytes, compute
  the segment that contains `sh_offset` and check
  `sh_addr - sh_offset == p_vaddr - p_offset` and that the address range lies
  in `[p_vaddr, p_vaddr + p_memsz)`. On a mismatch: *warning* "section `.text`
  sh_addr 0x… disagrees with PT_LOAD #2 (expected 0x…)". Addresses used for
  analysis come from the segment mapping.

### T10. Program header table overlapping the ELF header ("tiny ELF")

- **Changed.** `e_phoff` points *into* the ELF header, so header fields and
  program header fields share bytes. Code can also be placed inside the
  headers. The Teensy article builds a 45-byte i386 executable this way. Each
  stage overlaps more, and the last one even drops trailing bytes, relying on
  the kernel to zero-fill. [cited] Cozzi et al.: three Mumblehard samples
  "declared a single segment starting from the 44th byte of the ELF header
  itself and zeroed out any field unused at runtime" ("Overlapping ELF
  header/segment", 2 samples in Table II). [cited]
- **Built here (aarch64 ELF64, 124 bytes, t60).** `e_phoff = 0x38`, so
  `p_type` overlaps `e_phnum` + `e_shentsize`, and `p_flags` overlaps `e_shnum`
  + `e_shstrndx`. `p_type = 1` gives `e_phnum = 1`, `e_shentsize = 0`.
  `p_flags = 5` (R+X) gives `e_shnum = 5`, `e_shstrndx = 0`. One `PT_LOAD` maps
  the whole file at 0x400000. The code (`mov x0,#42; mov x8,#93; svc #0`) is at
  0x70. t61 is the same file with garbage in every field the kernel ignores:
  `e_ident[4..16] = ff "GARBAGE" 00 "!!" 01`, `e_version = 0xcafebabe`,
  `e_shoff = 0x4141…`, `e_flags`, `e_ehsize = 0x0bad`.
- **Why tools break.** Observed:
  - `objdump`/`nm` "file format not recognized" (t60, t61).
  - `readelf` "Section headers are not available!" (t60), and five warnings on
    t61.
  - `unforge` reads t60 correctly but stops on t61 with "unsupported EI_CLASS
    255".
  
  The binaryresearch.github.io article (2019) shows `gdb` "not in executable
  format", radare2 warnings and wrong values, and Capstone linear sweep
  decoding data as code on such files. [cited]
- **Kernel verdict.** Both exit 42 [run], so the code ran.
  - *Not tested on aarch64:* the Teensy trick of *omitting trailing header
    bytes*.
  - The kernel reads the header from `bprm->buf`, a fixed-size buffer filled
    from the file. [NOT VERIFIED] whether bytes past a short file are
    guaranteed zero in v7.0. The article says Linux zero-fills.
  - The program header table read (`elf_read`) needs the full
    `e_phnum * e_phentsize` bytes to be in the file [source]. So only header
    fields *before* the end of the last program header can be dropped.
- **Build.** See the tiny-ELF block in the appendix.
- **Tolerant reader.** Header and program header decoding are independent
  reads of the same bytes, and overlap is allowed. Diagnostics:
  - *info* "program header table overlaps the ELF header [0x38, 0x40)";
  - *warning* "e_shnum=5 but e_shoff=0";
  - *info* "entry point 0x400070 is inside the header area / not inside any
    section".
  
  Layout comes from `e_machine` (§2 rule 4), so t61's `EI_CLASS = 0xff` is a
  diagnostic, not a fatal error.

### T11. Program header table inside or outside a `PT_LOAD`

- **Changed.** Normally the program header table is covered by the first
  `PT_LOAD` (and `PT_PHDR` describes it). In s24 the table is copied to EOF,
  outside every `PT_LOAD`, and `e_phoff` points at the copy. `PT_PHDR` still
  names the old address. gABI: `PT_PHDR` "may occur only if the program header
  table is part of the memory image of the program" and "must precede any
  loadable segment entry". [source: gABI ch5.pheader]
- **Why tools break.** Static tools do not care: no diagnostic from
  `readelf`/`objdump`/`unforge`. Run-time consumers do (next point). The
  reverse case, a table that a `PT_LOAD` covers but that has no `PT_PHDR`, is
  common in tiny files and harmless.
- **Kernel verdict.** The kernel loads it, but `AT_PHDR` becomes `0 + load_bias`
  because no `PT_LOAD` covers `e_phoff` [source]. The static musl program then
  dies with **SIGSEGV** (s24) [run]: `static_init_tls()` walks `AT_PHDR`
  [source]. That the crash is in musl's walk and not in `exec` itself is
  inferred from the two sources; the run does not tell them apart. A program
  that does not read `AT_PHDR` would survive. [NOT VERIFIED by a run]
- **Build.** Append a copy of the program header table (8-aligned) at EOF and
  write its offset to `e_phoff` (0x20).
- **Tolerant reader.** Parse the table at `e_phoff` as usual. Diagnostics:
  - *warning* "program header table [x, y) is not inside any PT_LOAD: AT_PHDR
    will be invalid at run time";
  - *warning* "PT_PHDR (p_vaddr 0x…) disagrees with where PT_LOAD maps
    e_phoff".

### T12. `e_ident` garbage: `EI_CLASS`, `EI_DATA`, `EI_VERSION`, `EI_OSABI`, `EI_PAD`

- **Changed** (on both the static and the dynamic base):
  - `EI_CLASS = 1` (claims ELF32) in s16 and d16, `EI_CLASS = 0x55` in s17
    and d17;
  - `EI_DATA = 2` (claims big-endian) in s18 and d18, `EI_DATA = 0` in s19;
  - `EI_VERSION = 0` and `e_version = 0` in s20 and d20;
  - `EI_OSABI = 9` (FreeBSD), `EI_ABIVERSION = 0x42`, `EI_PAD = "GARBAGE"`
    in s21 and d21.
  
  Cozzi et al.: Mumblehard samples claim FreeBSD in `EI_OSABI` and still run on
  Linux. [cited]
- **gABI.** `ELFCLASSNONE` and `ELFDATANONE` are "Invalid". For `EI_PAD`:
  "programs that read object files should ignore them". [source]
- **Why tools break.** This is the single most damaging trick for parsers,
  because the class and byte order decide how *every other byte* is read.
  Observed:
  - `objdump`/`nm` "file format not recognized" for every `EI_CLASS`,
    `EI_DATA` and `EI_VERSION` variant. Even `EI_VERSION = 0` alone is enough
    for BFD. OSABI/PAD garbage is accepted.
  - `readelf` reads s16/d16 as ELF32 and prints nonsense, with a warning such
    as "possibly corrupt ELF file header…". It reads s18/d18 as big-endian
    nonsense.
  - `unforge` refuses s17/s19 (unsupported class/data). It **misreads s16/d16
    as ELF32 with exit status 0**: "Program header count: 0", "There are no
    program headers", the e_ehsize warning only. It misreads s18/d18 as
    big-endian and then fails on a program header table "at
    0x4000000000000000".
- **Kernel verdict.** All run [run]: s16–s21 and d16–d21. The kernel never
  reads these bytes, and glibc does not re-verify the main program (§1.2)
  [source].
- **Build.** Write one byte at offset 4 (`EI_CLASS`), 5 (`EI_DATA`), 6
  (`EI_VERSION`), 7 (`EI_OSABI`), 8 (`EI_ABIVERSION`), or 9..16 (`EI_PAD`), and
  4 bytes at 0x14 (`e_version`).
- **Tolerant reader.**
  - **Layout from `e_machine` (loader-faithful).** Decode `e_machine` (offset
    0x12, same place in both classes) in both byte orders. Pick the order in
    which it is a supported machine. That machine fixes the class on Linux
    (`EM_AARCH64` → ELF64, `EM_386`/`EM_ARM` → ELF32).
  - Then cross-check: `e_phentsize` must be 56 (ELF64) or 32 (ELF32), and
    `e_ehsize`, if sane, 64 or 52.
  - Diagnostic: *warning* "EI_CLASS says ELFCLASS32 but e_machine EM_AARCH64
    is a 64-bit machine on Linux; parsed as ELF64 (the kernel ignores
    EI_CLASS)". Same for `EI_DATA`.
  - `EI_VERSION`/`e_version`/`EI_OSABI`/`EI_PAD`: *info* only, with
    "a shared library with this header would be refused by glibc ld.so".
  - **Limits of the heuristic.** [partly NOT VERIFIED]
    - `EM_X86_64` is also used by x32 (ELF32), and `EM_MIPS` and `EM_PPC*`
      exist in both classes. For those machines the reader should try both
      layouts and keep the one whose program header table decodes
      consistently. Report "ambiguous" if both do.
    - Big-endian aarch64 kernels exist (`CONFIG_CPU_BIG_ENDIAN`). There, the
      byte order that makes `e_machine` valid is big-endian. The
      "decode `e_machine` both ways" rule handles that; [NOT VERIFIED] by a
      run.
  - Do not let a wrong `EI_CLASS` produce a clean-looking result with exit 0.
    That is worse than an error (current `unforge` on s16/d16).

### T13. `e_ehsize` garbage

- **Changed.** `e_ehsize = 0` (s22, d22) or `0xffff` (s23). Teensy: Linux "pays
  it no mind". [cited]
- **Why tools break.** Tools that seek to `e_ehsize` to find the next structure,
  or that take it as the header size, misread. Observed: binutils accepts it
  silently. `unforge` warns and continues (correct).
- **Kernel verdict.** Runs [run]. Not read [source].
- **Build.** Write 2 bytes at 0x34.
- **Tolerant reader.** Use the fixed header size for the class. Report *info*
  "e_ehsize 0 ≠ 64". Note that `sstrip` uses `e_ehsize` when it computes the
  kept size, so a tiny `e_ehsize` changes what `sstrip` keeps.

### T14. `p_filesz` past EOF: truncated last segment

- **Changed.**
  - s25, d25: the file is cut 0x10 bytes into the last `PT_LOAD`, which is
    writable and has `p_memsz > p_filesz`.
  - s26: after sstrip, the last `PT_LOAD` gets
    `p_filesz = p_memsz = old p_memsz + 0x10000`, so it claims file bytes far
    past EOF.
  - t62–t64: single-segment tiny files with `p_filesz = 0x1100` in a 124-byte
    file: t62 `RWX` with `p_memsz = 0x3000`, t63 `R-X` with
    `p_memsz = 0x3000`, t64 `R-X` with `p_memsz = p_filesz`. t65 is the control.
- **Why tools break.** Tools that read a whole segment fail or pad silently.
  Observed: binutils gives no diagnostic for s26. For s25/d25 the cut also
  removed the section table (`objdump` "file format not recognized"). Emulators
  and sandboxes that copy segments may differ from the kernel. [NOT VERIFIED]
- **Kernel verdict** [source + run]:
  - `vm_mmap` past EOF succeeds, so the mapping exists. A **read-only** segment
    loads: t63 and t64 exit 42. `padzero` failing is ignored when the segment is
    not writable. Touching a page that lies wholly past EOF raises **SIGBUS**:
    s26 dies with signal 7 when the program uses its `.bss`, which is now
    "file-backed".
  - A **writable** segment with `p_memsz > p_filesz` whose last file page lies
    past EOF makes `padzero()` fail. `elf_load` returns `-EFAULT` after the
    point of no return, and exec kills the task with **SIGSEGV before any
    instruction**: t62 dies with SIGSEGV although its code would `exit(42)`.
  - s25 and d25 (SIGSEGV) fit the same path. That they die in the kernel rather
    than in user space is inferred, not observed.
- **Build.** Truncate the file (s25). Or edit `p_filesz`/`p_memsz` (+0x20/+0x28
  in each 56-byte program header) of the last `PT_LOAD` (s26).
- **Tolerant reader.** Keep the segment. Its file-backed view is clipped to EOF.
  Diagnostics:
  - *warning* "PT_LOAD #4 claims file bytes [a, b) but the file ends at c";
  - plus a *predicted run-time effect*: "writable with p_memsz > p_filesz and
    the last file page is past EOF: the kernel aborts exec (SIGSEGV)", or
    "read-only: maps, SIGBUS when page ≥ … is touched".
  
  Content past EOF is unknown, not zero, except within the last partial page.
  The kernel's mapping zero-fills only up to the page boundary.

### T15. `PT_LOAD` overlap and order (also: non-power-of-two `p_align`)

- **Changed.**
  - s27, d27: the `PT_GNU_EH_FRAME` slot becomes a second copy of the R-X
    `PT_LOAD`.
  - s28: that slot becomes a `PT_LOAD` mapping file page 0 (the headers) over
    the first page of the R-X segment.
  - s29, d29: the first and last `PT_LOAD` entries are swapped, so the table
    is not sorted.
  - s30: `p_align = 3` on every `PT_LOAD`.
  
  gABI: "Loadable segment entries in the program header table appear in
  ascending order, sorted on the p_vaddr member", and `p_align` "should be a
  positive, integral power of 2". [source]
- **Why tools break.** Tools that build an address → offset map often assume
  sorted, disjoint segments and binary-search them. With an overlap, *which*
  bytes are at an address depends on the rule used. Observed: binutils is
  silent on overlap and order. `objdump`/`nm` warn "has a program header with
  invalid alignment" for s30.
- **Kernel verdict** [source + run]:
  - Segments are mapped in table order. Every one after the first uses
    `MAP_FIXED`, so **later entries override earlier ones**. s28 dies with
    **SIGILL**, because the header bytes now sit where the entry point's code
    was. s27 (identical overlap) runs.
  - Order is not checked: s29 and d29 run. For `ET_EXEC` only the first entry
    in the table uses `MAP_FIXED_NOREPLACE`.
  - Non-power-of-two `p_align` is skipped: s30 runs.
  - [NOT VERIFIED]: what happens when an `ET_DYN`'s first-in-table `PT_LOAD` is
    not the lowest address. `total_mapping_size` uses min/max over all
    `PT_LOAD`s, but `load_bias` is computed from the first entry's `p_vaddr`. I
    did not trace whether a high first entry can leave lower segments outside
    the reserved range.
- **Build.** Overwrite a non-essential program header (e.g. `PT_GNU_EH_FRAME`,
  `PT_NOTE`) with a `PT_LOAD`. Swap two 56-byte entries. Set `p_align` (+0x30).
- **Tolerant reader.** Build the memory map as the kernel does: apply `PT_LOAD`s
  in table order, page-granular, later ones replacing earlier ones. Keep the
  history, so "address X is backed by PT_LOAD #7 (overrides #2)" can be shown.
  Diagnostics: *warning* "PT_LOAD #7 overlaps #2 in [a, b); #7 wins at run
  time"; *info* "PT_LOAD entries not sorted by p_vaddr"; *info* "p_align 3 is
  not a power of two (ignored by the kernel)". Note: removing
  `PT_GNU_EH_FRAME` to make room also hides `.eh_frame_hdr` from unwinders that
  use `dl_iterate_phdr`. A reader should look for it by other means too
  (section, or a scan for the `.eh_frame_hdr` version byte 1 + encodings).
  [the scan heuristic is NOT VERIFIED]

### T16. `PT_DYNAMIC` pointing at bad data

- **Changed** (dynamic glibc base):
  - d40: `PT_DYNAMIC` `p_offset = 0xdeadbeef`, `p_filesz = 0xffffffff`
    (`p_vaddr` unchanged);
  - d41: `p_vaddr` points into `.rodata`;
  - d46: `PT_DYNAMIC` turned into `PT_NULL`;
  - d42 (T06): the `.dynamic` *section header* is garbage.
- **Why tools break.** Tools read the dynamic table from `p_offset`/`p_filesz`
  or from the `.dynamic` section. `ld.so` reads it from `l_addr + p_vaddr` in
  memory. Observed: binutils printed no diagnostic for d40 or d41, so it shows
  a dynamic table the loader never uses (or misses the one it does use).
  [run for d40/d41 verdicts; the binutils decoding details are NOT VERIFIED
  line by line]
- **Verdict (kernel + glibc 2.36 ld.so)** [run + source `rtld.c`]:
  - d40 **runs**: `ld.so` ignores `p_offset`/`p_filesz`.
  - d41 dies with SIGSEGV: `ld.so` parses `.rodata` as `Elf64_Dyn`.
  - d46 dies with SIGSEGV: no dynamic table, but relocations are still needed.
  - The kernel never reads `PT_DYNAMIC`.
  - For musl static PIE see §1.3 (likely ignored at run time, NOT run).
- **Build.** Edit `p_offset`/`p_filesz`/`p_vaddr` of the `PT_DYNAMIC` entry
  (type 2), or set its `p_type` to 0.
- **Tolerant reader.** Locate the dynamic table **by `p_vaddr` through the
  `PT_LOAD` map**, as `ld.so` does. Report *warning* "PT_DYNAMIC p_offset 0x…
  disagrees with the file offset PT_LOAD maps p_vaddr to (0x…)". Decode entries
  until `DT_NULL` or the end of mapped file bytes, with a cap. Validate every
  `DT_*` address against the map: *warning* "DT_STRTAB 0x… is not mapped". If
  there is no `PT_DYNAMIC` while `PT_INTERP` exists: *warning* "dynamic
  executable without PT_DYNAMIC: ld.so will fail".

### T17. Symbol tables with garbage names, links, sizes or overlaps

- **Changed** (`static-musl-syms`, `.symtab` with 4117 entries):
  - y50: every `st_name = 0xffffffNN` (out of range of `.strtab`);
  - y51: `.symtab` `sh_link` = `.text` (not a string table);
  - y52: `sh_entsize = 0`, `sh_size += 7` (not a multiple of the entry size);
  - y53: every `STT_FUNC` gets the same `st_value` and
    `st_size = 0xffffffffffff` (all functions overlap);
  - y54: every `st_shndx = 0xfeee` (in the reserved range).
  
  On the dynamic base, d43 points the `.dynsym` `sh_link` at `.shstrtab`.
- **Why tools break.** Observed:
  - `nm` prints y50 with no error (empty names). `readelf` says "Link field (5)
    should index a string section" (y51) and "invalid sh_entsize of 0" (y52).
    `objdump`/`nm` say "file format not recognized" on y52. y53 and y54 give no
    diagnostic anywhere, so tools that place functions by
    `st_value`/`st_size` get one giant function.
  - d43: `readelf` prints 27 "corrupt string table index" errors. `nm` and
    `objdump` are silent (they use the dynamic tables differently,
    [NOT VERIFIED]).
  - `unforge`: y50 prints `<bad name 0x…>` per symbol (correct). y51 and y52
    are fatal ("unexpected section type 0x1", "entry size 0 is smaller than
    24").
- **Kernel verdict.** All run [run]. Static programs need no symbols at run
  time. For dynamic programs, `ld.so` uses `DT_SYMTAB`/`DT_STRTAB`, not section
  headers, so d43 runs. Garbage *in the dynamic symbol bytes themselves* would
  break symbol lookup for relocations. [not built here]
- **Build.** Rewrite fields in each 24-byte `Elf64_Sym` (`st_name` +0, `st_info`
  +4, `st_shndx` +6, `st_value` +8, `st_size` +0x10), or `sh_link`/`sh_entsize`
  in the section header.
- **Tolerant reader.**
  - Per symbol: decode what is valid. Bad name → "unnamed, raw st_name kept"
    plus one aggregated *warning* "4116 symbols have st_name outside .strtab".
  - `sh_link` not a string table → keep the symbols without names, and
    *warning*.
  - `sh_entsize` 0 or odd → use `sizeof(Sym)` and *warning*.
  - `sh_size` not a multiple → use `floor(size/24)` entries and *warning*
    "trailing 7 bytes".
  - Reserved `st_shndx` → *warning* (once, with a count).
  - Overlapping `STT_FUNC` ranges → *warning* "N function symbols overlap";
    stage 3 should not trust symbol sizes over `.eh_frame` FDE ranges.
  - Symbols are claims. Function boundaries should be checked against
    `.eh_frame` and against the code itself.

### T18. UPX-like packed layout

- **Changed.** The real code is compressed. A small stub decompresses it into
  memory at run time.
  - Typical layout [cited / NOT VERIFIED here]: no section header table; few
    `PT_LOAD`s, one with `p_memsz` much larger than `p_filesz` (room for the
    unpacked image); high entropy; UPX's own structures (`l_info` with the
    `"UPX!"` magic `l_magic` right after the program headers, `p_info`,
    `b_info` blocks, and a "PackHeader" near EOF).
  - JPCERT/CC (2022): `l_info` is at offset 116 (`0x74`) in the samples it
    describes. For ELF32 that is `52 + 2*32`, i.e. right after two program
    headers (my arithmetic). Its YARA rule reads a 4-byte magic at
    `filesize - 0x24`.
- **What malware changes.**
  - JPCERT/CC: usually only `l_magic` (Mirai uses a different value in each
    sample; a Lazarus-linked sample uses `"MEMS"`); sometimes `p_filesize` and
    `p_blocksize` in `p_info` are zeroed. nullteilerfrei.de shows Mozi zeroing
    them, so `upx -d` fails with "p_info corrupted".
  - Cozzi et al. Table VIII: 189 vanilla UPX and 188 custom UPX variants among
    10,548 samples. The variants used a different magic (129), modified UPX
    strings (55), or inserted junk bytes (126). "All these samples share the
    same underlying packing structure and the same compression algorithm".
  
  [cited]
- **Why tools break.** Static tools see only the stub. `upx -d` refuses a
  tampered header. Section-based tools see nothing (T01).
- **Kernel verdict.** Packed files run by design. [NOT VERIFIED here]: I could
  not pack a sample in this session (downloading and running the UPX binary was
  not permitted), so no run.
- **Build.** `upx -o packed orig` (UPX 4.x). Then overwrite every `"UPX!"`
  occurrence with another 4-byte value, and/or zero the two 32-bit fields after
  `p_progid` in `p_info`. The exact offsets depend on the UPX version
  [NOT VERIFIED].
- **Tolerant reader.** Parse it as an ordinary ELF (it is one). Diagnostics:
  - *info* "likely packed": no sections + an executable `PT_LOAD` with
    `p_memsz ≫ p_filesz` + high entropy;
  - *info* "UPX structures found (l_info at 0x…, magic 'UPX!' / altered magic
    0x…)", found by structure position as well as by magic string;
  - stage 3 and later must say "analysed the stub only".
  
  Unpacking is out of scope for the loader. A future stage could unpack by
  emulating the stub, as Cozzi et al. did with Unicorn. [cited]

### T19. Controls: what the kernel *does* enforce

These are not anti-analysis techniques. They show where the kernel stops
tolerating input. A tolerant reader should name these in its "would not run"
diagnostic.

| variant | change | verdict | what produced it |
|---|---|---|---|
| s31 | `e_phentsize = 32` | `Exec format error (os error 8)` | **kernel** (`load_elf_phdrs`) [run + source] |
| s32 | `e_machine = 62` (x86-64), aarch64 code | **SIGSEGV** | **NOT the kernel**: the file matches the x86-64 `binfmt_misc` magic, so qemu-x86_64 or Rosetta ran aarch64 bytes as x86 code. A native arm64 kernel without such a handler would return `ENOEXEC` from `elf_check_arch` [source]. This is the trap described in §0.1 |
| (not built) | `e_type` not `ET_EXEC`/`ET_DYN` | `ENOEXEC` | [source] |
| (not built) | `e_phnum * 56 > 65536`, or `e_phnum = 0` | `ENOEXEC` | [source] |
| (not built) | program header table not fully inside the file | error from `elf_read` (`-EIO`) | [source] |
| (not built) | `p_filesz > p_memsz` on any `PT_LOAD` | `-EINVAL` after the point of no return, so SIGSEGV | [source] |
| (not built) | `PT_INTERP` `p_filesz < 2`, `> PATH_MAX`, or not NUL-terminated | `ENOEXEC` | [source] |

---

## 4. Results matrix

Kernel column: aarch64 `7.0.12-linuxkit`, real `binfmt_elf`, except s32 (an
emulator, see T19). Exit status 0 is normal for the bases (`panics` with no
arguments, `true`). Tool columns: `rc`, or "ok" for rc 0 without a relevant
diagnostic.

| file | technique | kernel run | readelf 2.40 | objdump 2.40 | nm 2.40 | unforge (2026-11-16) |
|---|---|---|---|---|---|---|
| s00-baseline | – | exit 0 | ok | ok | no symbols | ok |
| s01-shdr-zeroed | T01 | exit 0 | ok | ok, disassembles nothing | no symbols | ok |
| s02-sstrip | T01 | exit 0 | ok | ok, nothing | no symbols | ok |
| s03-shoff-garbage | T02 | exit 0 | error, continues | format not recognized | format not recognized | **rc 1** (section table outside file) |
| s04-shoff-past-eof | T02 | exit 0 | error, continues | not recognized | not recognized | **rc 1** |
| s05-shnum-ffff | T03 | exit 0 | error, continues | not recognized | not recognized | **rc 1** |
| s06-shentsize-1 | T04 | exit 0 | error, continues | not recognized | not recognized | **rc 1** |
| s07-shstrndx-out-of-range | T05 | exit 0 | ok (no names) | warning | warning | **rc 1** |
| s08-shstrndx-is-text | T05 | exit 0 | ok (garbage names) | warning | warning | ok (garbage names, no warning) |
| s09-text-size-huge | T06 | exit 0 | warning | warning | warning | ok, no warning |
| s10-rodata-offset-past-eof | T06 | exit 0 | silent | warning | warning | ok, no warning |
| s11-decoy-swap-text-rodata-names | T07 | exit 0 | silent | disassembles "`.rodata`" | no symbols | ok, no warning |
| s12-text-is-nobits | T07 | exit 0 | silent | **19 lines: main code hidden** | no symbols | ok, no warning |
| s13-progbits-all-overlap-text | T08 | exit 0 | silent | code ×3 | no symbols | ok, no warning |
| s14-2000-symtabs-same-bytes | T08 | exit 0 | **3,236,000 warnings** | "multiple symbol tables" | same | **rc 1** (tables overlap) |
| s15-section-addr-disagree-with-segments | T09 | exit 0 | silent | silent | no symbols | ok, no warning |
| s16-ei-class-32 | T12 | exit 0 | misread as ELF32 | not recognized | not recognized | **misread as ELF32, rc 0** |
| s17-ei-class-0x55 | T12 | exit 0 | warning | not recognized | not recognized | **rc 1** unsupported EI_CLASS |
| s18-ei-data-be | T12 | exit 0 | misread as BE | not recognized | not recognized | **rc 1** after BE misread |
| s19-ei-data-0 | T12 | exit 0 | ok | not recognized | not recognized | **rc 1** unsupported EI_DATA |
| s20-ei-version-0-e_version-0 | T12 | exit 0 | ok | not recognized | not recognized | warnings, ok |
| s21-osabi-freebsd-pad-garbage | T12 | exit 0 | ok | ok | ok | ok |
| s22-ehsize-0 | T13 | exit 0 | ok | ok | ok | warning, ok |
| s23-ehsize-ffff | T13 | exit 0 | ok | ok | ok | warning, ok |
| s24-phdr-outside-every-load | T11 | **SIGSEGV** (musl reads `AT_PHDR`) | silent | silent | – | ok, no warning |
| s25-truncated-inside-last-load | T14 | **SIGSEGV** | error, continues | not recognized | not recognized | **rc 1** |
| s26-last-load-filesz-past-eof | T14 | **SIGBUS** | silent | silent | – | ok, no warning |
| s27-ptload-duplicate-of-rx | T15 | exit 0 | silent | silent | – | ok, no warning |
| s28-ptload-later-overrides-text | T15 | **SIGILL** (later map wins) | silent | silent | – | ok, no warning |
| s29-ptload-not-sorted | T15 | exit 0 | silent | silent | – | ok, no warning |
| s30-palign-not-power-of-two | T15 | exit 0 | silent | warning | warning | ok, no warning |
| s31-phentsize-wrong | T19 | **ENOEXEC** (kernel) | error | ok | ok | rc 1 |
| s32-machine-wrong | T19 | SIGSEGV **(emulator via binfmt_misc, not kernel)** | ok | rc 1, unknown architecture | ok | ok |
| t60-tiny-phdr-overlaps-ehdr | T10 | exit 42 | "Section headers are not available!" | not recognized | not recognized | ok (no warning for e_shnum=5) |
| t61-tiny-overlap-all-unused-fields-garbage | T10/T12 | exit 42 | 5 warnings | not recognized | not recognized | **rc 1** unsupported EI_CLASS 255 |
| t62-rwx-filesz-past-eof-memsz-bigger | T14 | **SIGSEGV before user code** | (not run) | | | (not run) |
| t63-rx-filesz-past-eof-memsz-bigger | T14 | exit 42 | (not run) | | | (not run) |
| t64-rx-filesz-past-eof | T14 | exit 42 | (not run) | | | (not run) |
| t65-control | – | exit 42 | (not run) | | | (not run) |
| d00-baseline | – | exit 0 | ok | ok | no symbols | ok |
| d01-shdr-zeroed | T01 | exit 0 | ok | ok | no symbols | ok |
| d02-sstrip | T01 | exit 0 | ok | ok | no symbols | ok |
| d03-shoff-garbage | T02 | exit 0 | error, continues | not recognized | not recognized | **rc 1** |
| d16-ei-class-32 | T12 | exit 0 | misread | not recognized | not recognized | **misread as ELF32, rc 0** |
| d17-ei-class-0x55 | T12 | exit 0 | warning | not recognized | not recognized | **rc 1** |
| d18-ei-data-be | T12 | exit 0 | misread | not recognized | not recognized | **rc 1** after misread |
| d20-ei-version-0-e_version-0 | T12 | exit 0 | ok | not recognized | not recognized | warnings, ok |
| d21-osabi-freebsd-pad-garbage | T12 | exit 0 | ok | ok | ok | ok |
| d22-ehsize-0 | T13 | exit 0 | ok | ok | ok | warning, ok |
| d25-truncated-inside-last-load | T14 | **SIGSEGV** | error, continues | not recognized | not recognized | **rc 1** |
| d27-ptload-duplicate-of-rx | T15 | exit 0 | silent | silent | – | ok |
| d29-ptload-not-sorted | T15 | exit 0 | silent | silent | – | ok |
| d40-pt_dynamic-offset-filesz-garbage | T16 | **exit 0** (ld.so uses `p_vaddr`) | silent | silent | – | ok, no warning |
| d41-pt_dynamic-vaddr-into-rodata | T16 | SIGSEGV (ld.so) | silent | silent | – | ok, no warning |
| d42-dynamic-section-header-garbage | T06 | exit 0 | warning | warning | warning | ok, no warning |
| d43-dynsym-sh_link-to-shstrtab | T17 | exit 0 | 27 errors | silent | – | ok, no warning |
| d44-dynsym-section-points-at-text | T07 | exit 0 | 62 errors | silent | – | ok, no warning |
| d45-interp-section-header-garbage | T06 | exit 0 | silent | warning | warning | ok, no warning |
| d46-pt_dynamic-removed | T16 | SIGSEGV (ld.so) | silent | silent | – | ok, no warning |
| y50-symtab-st_name-out-of-range | T17 | exit 0 | silent | silent | silent | ok, `<bad name 0x…>` |
| y51-symtab-sh_link-to-text | T17 | exit 0 | warning | silent | silent | **rc 1** |
| y52-symtab-entsize-0-size-ragged | T17 | exit 0 | error | not recognized | not recognized | **rc 1** |
| y53-symtab-funcs-all-same-addr-huge-size | T17 | exit 0 | silent | silent | silent | ok, no warning |
| y54-symtab-st_shndx-garbage | T17 | exit 0 | silent | silent | silent | ok, no warning |

"silent" means rc 0 with no warning, although the file is anomalous. These are
the cases where a tool *misleads* rather than fails. **Every row except s31
(and s32, which is not a kernel verdict) is a file the kernel accepted**,
including the ones that then crashed in user space. That makes them inputs a
tolerant reader must parse.

Counts for the current `unforge` (from the table):

- 15 files the kernel loads are rejected outright (rc 1): s03–s07, s14, s17,
  s19, s25, t61, d03, d17, d25, y51, y52. s18 and d18 also fail with rc 1,
  after a misread.
- 2 are silently misread with exit 0: s16, d16.
- Roughly 25 anomalies get no diagnostic (every "ok, no warning").

---

## 5. Open points and things not verified

- **UPX (T18)** was not reproduced: running the UPX release binary was not
  permitted in this session. All T18 layout details are from JPCERT/CC, Cozzi et
  al. and nullteilerfrei.de, and are not checked against UPX source.
- **Short files (Teensy's dropped trailing bytes).** Whether v7.0 zero-fills
  `bprm->buf` past EOF was not checked. No aarch64 file was built that relies
  on it.
- **x86-64 with x32** and `EI_CLASS = 1` (§1.1): handler order not checked.
- **`ET_DYN` whose first-in-table `PT_LOAD` is not the lowest one** (T15): not
  traced.
- **Per-architecture `e_flags` checks** (`arch_check_elf`, MIPS/ARM ABI
  flags): not checked. aarch64 and x86-64 do not use them in `elf_check_arch`
  (source above).
- **musl static PIE ignoring a bad `PT_DYNAMIC`**: from source only.
- **Cause of the s24/s25/d25 SIGSEGVs** (kernel abort vs. user-space fault): it
  is inferred from source. t62 proves the kernel-abort path exists, because its
  code would have exited 42.
- **Malware prevalence** numbers are from Cozzi et al. (2018 dataset) only. I
  have no newer primary measurement.
- **binutils bug numbers** in T03 come from a search; I did not open the
  reports.
- **Big-endian targets.** All runs were little-endian aarch64. For
  `testdata/bin/{powerpc64,s390x}-*` the kernel side could only be run under
  qemu-user (emulator verdict, §0.1), so it was not done.

## 6. Sources

Primary sources (read for this document):

- Linux kernel v7.0, `fs/binfmt_elf.c` (`load_elf_binary`, `load_elf_phdrs`,
  `elf_map`, `elf_load`, `padzero`, `total_mapping_size`, `maximum_alignment`,
  `create_elf_tables`), `fs/exec.c` (`point_of_no_return`,
  `force_fatal_sig(SIGSEGV)`), `arch/arm64/include/asm/elf.h` and
  `arch/x86/include/asm/elf.h` (`elf_check_arch`, `compat_elf_check_arch`).
  https://github.com/torvalds/linux/tree/v7.0
- glibc 2.44 (commit c3a3a9808ad3), `elf/dl-load.c` (`open_verify`),
  `elf/rtld.c` (main-map program header scan, `PT_DYNAMIC` →
  `l_ld = l_addr + p_vaddr`). Debian's 2.36 build was the one executed.
- musl v1.2.6, `src/env/__init_tls.c` (`static_init_tls`), `ldso/dlstart.c`
  (`_dlstart_c`).
- System V gABI, https://www.sco.com/developers/gabi/latest/ : `ch4.eheader.html`
  (`e_shoff`/`e_phoff` "holds zero", `EI_CLASS`/`EI_DATA` values, `EI_PAD`
  "should ignore"), `ch4.sheader.html` ("Sections in a file may not overlap",
  `SHT_NOBITS`, `SHN_LORESERVE` escape), `ch5.pheader.html` (ascending
  `p_vaddr`, `p_filesz <= p_memsz`, `PT_PHDR` rules, `p_align`).
- ELFkickers `sstrip/sstrip.c` (Brian Raiter),
  https://github.com/BR903/ELFkickers (`getmemorysize`, `modifyheaders`).

Published analyses (cited, not reproduced unless the text says so):

- Brian Raiter, "A Whirlwind Tutorial on Creating Really Teensy ELF Executables
  for Linux", https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
  (undated; fields Linux checks or ignores, 45-byte overlapped ELF).
- E. Cozzi, M. Graziano, Y. Fratantonio, D. Balzarotti, "Understanding Linux
  Malware", IEEE S&P 2018, https://www.s3.eurecom.fr/docs/oakland18_cozzi.pdf
  (Table II "ELF header manipulation", Table III tool failures for readelf
  2.26.1 / GDB 7.11.1 / pyelftools 0.24, Table VIII packers, §"Anomalous ELF" /
  "Invalid ELF").
- binaryresearch, "Analyzing ELF Binaries with Malformed Headers, Part 1",
  2019, https://binaryresearch.github.io/2019/09/17/Analyzing-ELF-Binaries-with-Malformed-Headers-Part-1-Emulating-Tiny-Programs.html
- g1inko, "Weird ELFs, or a tale of breaking parsers once again", tmp.0ut
  vol. 3, https://tmpout.sh/3/13.html (Melkor-mutated section tables: GDB
  refused 98/100, the kernel ran 84/100; edb-debugger crashes, CVE-2023-27734;
  radare2 hangs fixed in 5.8.4).
- JPCERT/CC, "Anti-UPX Unpacking Technique", 2022,
  https://blogs.jpcert.or.jp/en/2022/03/anti_upx_unpack.html
- nullteilerfrei, "UPX packed ELF binaries of the Peer-to-Peer Botnet Family
  Mozi", 2019, https://blag.nullteilerfrei.de/2019/12/26/upx-packed-elf-binaries-of-the-peer-to-peer-botnet-family-mozi/
- Nozomi Networks, "Automatic restoration of corrupted UPX-packed samples",
  https://nozominetworks.com/blog/automatic-restoration-of-corrupted-upx-packed-samples
- binutils bugzilla, fuzz-found readelf crashes on crafted ELF (not opened
  individually): https://sourceware.org/bugzilla/show_bug.cgi?id=21135 ,
  …?id=21142 , …?id=22552 , …?id=33697

---

## Appendix A. Generator (`mutate.py`)

The script used to produce every `s*`, `d*`, `y*` and `t*` file above. Run it
with the three bases from §0.2 in one directory (`static-musl`,
`static-musl-syms`, `true-glibc`):

```sh
python3 -I mutate.py <bases-dir> <out-dir>     # writes 64 files
```

It handles ELF64 little-endian only, and assumes the base has the named
sections (`.text`, `.rodata`, `.symtab`, `.dynamic`, …) and a
`PT_GNU_EH_FRAME` slot. Its output was byte-identical across two runs.

```python
"""Generate anomalous ELF64 little-endian variants from normal binaries."""
import os, struct, sys

B, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)

class Elf:
    def __init__(s, data):
        s.d = bytearray(data)
    # ELF header
    def eh(s, name, val=None):
        f = {'e_type':(16,'H'),'e_machine':(18,'H'),'e_version':(20,'I'),'e_entry':(24,'Q'),
             'e_phoff':(32,'Q'),'e_shoff':(40,'Q'),'e_flags':(48,'I'),'e_ehsize':(52,'H'),
             'e_phentsize':(54,'H'),'e_phnum':(56,'H'),'e_shentsize':(58,'H'),'e_shnum':(60,'H'),
             'e_shstrndx':(62,'H')}[name]
        if val is None: return struct.unpack_from('<'+f[1], s.d, f[0])[0]
        struct.pack_into('<'+f[1], s.d, f[0], val)
    PH = ['p_type','p_flags','p_offset','p_vaddr','p_paddr','p_filesz','p_memsz','p_align']
    def ph(s, i):
        o = s.eh('e_phoff') + 56*i
        return dict(zip(s.PH, struct.unpack_from('<IIQQQQQQ', s.d, o)))
    def set_ph(s, i, p, off=None):
        o = (s.eh('e_phoff') if off is None else off) + 56*i
        struct.pack_into('<IIQQQQQQ', s.d, o, *[p[k] for k in s.PH])
    def phs(s): return [s.ph(i) for i in range(s.eh('e_phnum'))]
    SH = ['sh_name','sh_type','sh_flags','sh_addr','sh_offset','sh_size','sh_link','sh_info','sh_addralign','sh_entsize']
    def sh(s, i):
        o = s.eh('e_shoff') + 64*i
        return dict(zip(s.SH, struct.unpack_from('<IIQQQQIIQQ', s.d, o)))
    def set_sh(s, i, h):
        o = s.eh('e_shoff') + 64*i
        struct.pack_into('<IIQQQQIIQQ', s.d, o, *[h[k] for k in s.SH])
    def shs(s): return [s.sh(i) for i in range(s.eh('e_shnum'))]
    def name(s, i):
        st = s.sh(s.eh('e_shstrndx')); n = s.sh(i)['sh_name']
        o = st['sh_offset'] + n; e = s.d.index(b'\0', o)
        return s.d[o:e].decode()
    def idx(s, nm):
        for i in range(s.eh('e_shnum')):
            if s.name(i) == nm: return i
        raise KeyError(nm)

def load(n): return Elf(open(os.path.join(B, n), 'rb').read())
def save(n, e):
    p = os.path.join(OUT, n); open(p, 'wb').write(bytes(e.d)); os.chmod(p, 0o755)

def variants(base, prefix):
    v = {}
    def mk(name, fn):
        e = load(base); fn(e); v[prefix + name] = e
    mk('00-baseline', lambda e: None)
    def zero_sh(e): e.eh('e_shoff', 0); e.eh('e_shnum', 0); e.eh('e_shstrndx', 0)
    mk('01-shdr-zeroed', zero_sh)
    def sstrip(e):
        # Same arithmetic as ELFkickers sstrip getmemorysize()/modifyheaders().
        size = max(e.eh('e_phoff') + e.eh('e_phnum')*56, e.eh('e_ehsize'))
        for p in e.phs():
            if p['p_type'] != 0: size = max(size, p['p_offset'] + p['p_filesz'])
        if e.eh('e_shoff') >= size: zero_sh(e)
        del e.d[size:]
    mk('02-sstrip', sstrip)
    mk('03-shoff-garbage', lambda e: e.eh('e_shoff', 0xdeadbeefdeadbeef))
    mk('04-shoff-past-eof', lambda e: e.eh('e_shoff', len(e.d) + 0x1000))
    mk('05-shnum-ffff', lambda e: e.eh('e_shnum', 0xffff))
    mk('06-shentsize-1', lambda e: e.eh('e_shentsize', 1))
    mk('07-shstrndx-out-of-range', lambda e: e.eh('e_shstrndx', 0x1234))
    def shstr_text(e): e.eh('e_shstrndx', e.idx('.text'))
    mk('08-shstrndx-is-text', shstr_text)
    def text_huge(e):
        i = e.idx('.text'); h = e.sh(i); h['sh_size'] = 0xffffffffffff; e.set_sh(i, h)
    mk('09-text-size-huge', text_huge)
    def rodata_eof(e):
        i = e.idx('.rodata'); h = e.sh(i); h['sh_offset'] = len(e.d) + 0x100; e.set_sh(i, h)
    mk('10-rodata-offset-past-eof', rodata_eof)
    def decoy(e):
        a, b = e.idx('.text'), e.idx('.rodata')
        ha, hb = e.sh(a), e.sh(b); ha['sh_name'], hb['sh_name'] = hb['sh_name'], ha['sh_name']
        e.set_sh(a, ha); e.set_sh(b, hb)
    mk('11-decoy-swap-text-rodata-names', decoy)
    def text_nobits(e):
        i = e.idx('.text'); h = e.sh(i); h['sh_type'] = 8; e.set_sh(i, h)
    mk('12-text-is-nobits', text_nobits)
    def overlap(e):
        t = e.sh(e.idx('.text'))
        for i, h in enumerate(e.shs()):
            if h['sh_type'] == 1 and i != e.idx('.text'):
                h['sh_offset'], h['sh_size'] = t['sh_offset'], t['sh_size']; e.set_sh(i, h)
    mk('13-progbits-all-overlap-text', overlap)
    def many_symtabs(e):
        # Append a new section header table: the original entries plus 2000
        # SHT_SYMTAB entries that all describe the same .text bytes.
        t = e.sh(e.idx('.text')); old = e.shs(); stri = e.eh('e_shstrndx')
        while len(e.d) % 8: e.d.append(0)
        off = len(e.d); n = len(old) + 2000
        e.d += bytes(64*n); e.eh('e_shoff', off); e.eh('e_shnum', n)
        for i, h in enumerate(old): e.set_sh(i, h)
        for i in range(len(old), n):
            e.set_sh(i, dict(sh_name=0, sh_type=2, sh_flags=0, sh_addr=0, sh_offset=t['sh_offset'],
                             sh_size=t['sh_size'] // 24 * 24, sh_link=stri, sh_info=0,
                             sh_addralign=8, sh_entsize=24))
    mk('14-2000-symtabs-same-bytes', many_symtabs)
    def shift_addr(e):
        for i, h in enumerate(e.shs()):
            if h['sh_addr']: h['sh_addr'] += 0x100000; e.set_sh(i, h)
    mk('15-section-addr-disagree-with-segments', shift_addr)
    def ident(i, val):
        def f(e): e.d[i] = val
        return f
    mk('16-ei-class-32', ident(4, 1))
    mk('17-ei-class-0x55', ident(4, 0x55))
    mk('18-ei-data-be', ident(5, 2))
    mk('19-ei-data-0', ident(5, 0))
    def ver(e): e.d[6] = 0; e.eh('e_version', 0)
    mk('20-ei-version-0-e_version-0', ver)
    def osabi(e): e.d[7] = 9; e.d[8] = 0x42; e.d[9:16] = b'GARBAGE'
    mk('21-osabi-freebsd-pad-garbage', osabi)
    mk('22-ehsize-0', lambda e: e.eh('e_ehsize', 0))
    mk('23-ehsize-ffff', lambda e: e.eh('e_ehsize', 0xffff))
    def phdr_outside(e):
        # Copy the program header table to EOF (outside every PT_LOAD).
        n = e.eh('e_phnum'); o = e.eh('e_phoff'); tbl = bytes(e.d[o:o+56*n])
        while len(e.d) % 8: e.d.append(0)
        e.eh('e_phoff', len(e.d)); e.d += tbl
    mk('24-phdr-outside-every-load', phdr_outside)
    def last_load(e):
        return max((i for i, p in enumerate(e.phs()) if p['p_type'] == 1), key=lambda i: e.ph(i)['p_offset'])
    def trunc_last(e):
        p = e.ph(last_load(e)); del e.d[p['p_offset'] + 0x10:]
    mk('25-truncated-inside-last-load', trunc_last)
    def filesz_past_eof(e):
        i = last_load(e); p = e.ph(i)
        sstrip(e); p = e.ph(i)
        p['p_filesz'] = p['p_memsz'] = p['p_memsz'] + 0x10000; e.set_ph(i, p)
    mk('26-last-load-filesz-past-eof', filesz_past_eof)
    def slot(e, t):
        return next(i for i, p in enumerate(e.phs()) if p['p_type'] == t)
    def rx(e): return next(i for i, p in enumerate(e.phs()) if p['p_type'] == 1 and p['p_flags'] & 1)
    def overlap_same(e):
        s = slot(e, 0x6474e550); e.set_ph(s, e.ph(rx(e)))   # PT_GNU_EH_FRAME slot
    mk('27-ptload-duplicate-of-rx', overlap_same)
    def overlap_hostile(e):
        s = slot(e, 0x6474e550); p = dict(e.ph(rx(e)))
        p['p_offset'] = 0; p['p_filesz'] = p['p_memsz'] = 0x1000   # maps file page 0 over the start of the RX mapping
        p['p_vaddr'] = p['p_paddr'] = e.ph(rx(e))['p_vaddr'] & ~0xfff
        e.set_ph(s, p)
    mk('28-ptload-later-overrides-text', overlap_hostile)
    def unsorted(e):
        loads = [i for i, p in enumerate(e.phs()) if p['p_type'] == 1]
        a, b = loads[0], loads[-1]; pa, pb = e.ph(a), e.ph(b); e.set_ph(a, pb); e.set_ph(b, pa)
    mk('29-ptload-not-sorted', unsorted)
    def align3(e):
        for i, p in enumerate(e.phs()):
            if p['p_type'] == 1: p['p_align'] = 3; e.set_ph(i, p)
    mk('30-palign-not-power-of-two', align3)
    mk('31-phentsize-wrong', lambda e: e.eh('e_phentsize', 32))
    mk('32-machine-wrong', lambda e: e.eh('e_machine', 62))
    return v

out = {}
out.update(variants('static-musl', 's'))
def dmk(name, fn):
    e = load('true-glibc'); fn(e); out['d' + name] = e
def dslot(e, t): return next(i for i, p in enumerate(e.phs()) if p['p_type'] == t)
base_d = variants('true-glibc', 'd')
for k in ['d00-baseline','d01-shdr-zeroed','d02-sstrip','d03-shoff-garbage','d16-ei-class-32','d17-ei-class-0x55',
          'd18-ei-data-be','d20-ei-version-0-e_version-0','d21-osabi-freebsd-pad-garbage','d22-ehsize-0',
          'd25-truncated-inside-last-load','d27-ptload-duplicate-of-rx','d29-ptload-not-sorted']:
    out[k] = base_d[k]
def dyn_off(e):
    i = dslot(e, 2); p = e.ph(i); p['p_offset'] = 0xdeadbeef; p['p_filesz'] = 0xffffffff; e.set_ph(i, p)
dmk('40-pt_dynamic-offset-filesz-garbage', dyn_off)
def dyn_vaddr(e):
    i = dslot(e, 2); p = e.ph(i); p['p_vaddr'] = e.sh(e.idx('.rodata'))['sh_addr']; e.set_ph(i, p)
dmk('41-pt_dynamic-vaddr-into-rodata', dyn_vaddr)
def dyn_sec(e):
    i = e.idx('.dynamic'); h = e.sh(i); h['sh_offset'] = 0xdeadbeef; h['sh_size'] = 0x7fffffff; e.set_sh(i, h)
dmk('42-dynamic-section-header-garbage', dyn_sec)
def dynsym_link(e):
    i = e.idx('.dynsym'); h = e.sh(i); h['sh_link'] = e.idx('.shstrtab'); e.set_sh(i, h)
dmk('43-dynsym-sh_link-to-shstrtab', dynsym_link)
def dynsym_hdr(e):
    i = e.idx('.dynsym'); h = e.sh(i); h['sh_offset'] = e.sh(e.idx('.text'))['sh_offset']; e.set_sh(i, h)
dmk('44-dynsym-section-points-at-text', dynsym_hdr)
def interp_hdr(e):
    i = e.idx('.interp'); h = e.sh(i); h['sh_offset'] = 0xdeadbeef; e.set_sh(i, h)
dmk('45-interp-section-header-garbage', interp_hdr)
def no_dynamic_ph(e):
    i = dslot(e, 2); p = e.ph(i); p['p_type'] = 0; e.set_ph(i, p)
dmk('46-pt_dynamic-removed', no_dynamic_ph)

# Symbol-table variants on the static binary that still has .symtab.
def ymk(name, fn):
    e = load('static-musl-syms'); fn(e); out['y' + name] = e
def symtab(e): i = e.idx('.symtab'); return i, e.sh(i)
def y_names(e):
    i, h = symtab(e)
    for k in range(1, h['sh_size'] // 24):
        o = h['sh_offset'] + 24*k; struct.pack_into('<I', e.d, o, 0xffffff00 + (k & 0xff))
ymk('50-symtab-st_name-out-of-range', y_names)
def y_link(e):
    i, h = symtab(e); h['sh_link'] = e.idx('.text'); e.set_sh(i, h)
ymk('51-symtab-sh_link-to-text', y_link)
def y_entsize(e):
    i, h = symtab(e); h['sh_entsize'] = 0; h['sh_size'] += 7; e.set_sh(i, h)
ymk('52-symtab-entsize-0-size-ragged', y_entsize)
def y_overlap(e):
    i, h = symtab(e); first = None
    for k in range(1, h['sh_size'] // 24):
        o = h['sh_offset'] + 24*k
        info = e.d[o+4]
        if info & 0xf == 2:   # STT_FUNC
            if first is None: first = struct.unpack_from('<Q', e.d, o+8)[0]
            struct.pack_into('<QQ', e.d, o+8, first, 0xffffffffffff)
ymk('53-symtab-funcs-all-same-addr-huge-size', y_overlap)
def y_shndx(e):
    i, h = symtab(e)
    for k in range(1, h['sh_size'] // 24):
        o = h['sh_offset'] + 24*k; struct.pack_into('<H', e.d, o+6, 0xfeee)
ymk('54-symtab-st_shndx-garbage', y_shndx)

for n, e in out.items(): save(n, e)

# Hand-made tiny ELF64 for aarch64: the program header starts at offset 0x38 (code at 0x70),
# so p_type/p_flags overlap e_phnum/e_shentsize/e_shnum/e_shstrndx.
base = 0x400000
code = struct.pack('<III', 0xd2800540, 0xd2800ba8, 0xd4000001)   # mov x0,#42; mov x8,#93; svc #0
ehdr = bytearray(b'\x7fELF' + bytes([2, 1, 1]) + bytes(9))
ehdr += struct.pack('<HHIQQQIHH', 2, 183, 1, base + 0x70, 0x38, 0, 0, 64, 56)
assert len(ehdr) == 0x38
ph = struct.pack('<IIQQQQQQ', 1, 5, 0, base, base, 0x70 + len(code), 0x70 + len(code), 0x1000)
tiny = bytes(ehdr) + ph + code
assert len(tiny) == 0x70 + 12
save('t60-tiny-phdr-overlaps-ehdr', Elf(tiny))
# Same, but with garbage in every field the kernel does not read.
t = bytearray(tiny)
t[4:16] = b'\xffGARBAGE\x00!!\x01'          # EI_CLASS..EI_PAD
struct.pack_into('<I', t, 20, 0xcafebabe)    # e_version
struct.pack_into('<Q', t, 40, 0x4141414141414141)  # e_shoff
struct.pack_into('<IH', t, 48, 0x12345678, 0x0bad) # e_flags, e_ehsize
save('t61-tiny-overlap-all-unused-fields-garbage', Elf(bytes(t)))
# Tiny files whose single PT_LOAD claims more file bytes than exist.
def tiny_seg(flags, filesz, memsz, name):
    eh = bytearray(b'\x7fELF' + bytes([2, 1, 1]) + bytes(9))
    eh += struct.pack('<HHIQQQIHH', 2, 183, 1, base + 0x70, 0x38, 0, 0, 64, 56)
    ph = struct.pack('<IIQQQQQQ', 1, flags, 0, base, base, filesz, memsz, 0x1000)
    save(name, Elf(bytes(eh) + ph + code))
tiny_seg(7, 0x1100, 0x3000, 't62-rwx-filesz-past-eof-memsz-bigger')
tiny_seg(5, 0x1100, 0x3000, 't63-rx-filesz-past-eof-memsz-bigger')
tiny_seg(5, 0x1100, 0x1100, 't64-rx-filesz-past-eof')
tiny_seg(5, 0x7c, 0x7c, 't65-control')
print(len(out) + 6, 'files')
```

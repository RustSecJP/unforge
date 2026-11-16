# Anomalous-ELF corpus with the kernel as oracle

Small ELF files that break or mislead parsers, each run under Linux to record
whether the loader accepted it. The tests in `crates/unforge-elf/tests/` use
these verdicts as ground truth: a file the kernel loaded is a file a tolerant
reader must read.

| path | what |
|---|---|
| `TECHNIQUES.md` | the catalogue of techniques (T01-T19) these files implement |
| `LOADER_RULES.md` | what `fs/binfmt_elf.c` (Linux v7.0.12), glibc 2.44 and musl 1.2.6 check, with source lines |
| `seeds/marker.rs`, `seeds/build.sh` | the seed program (prints `UNFORGE_OK`, exits 42) and how the seed binaries were built |
| `seeds/bin/<arch>/marker-static[-pie]`, `seeds/SEEDS.txt` | the committed seed binaries and their sha256 |
| `files/<arch>/<name>.elf` | the generated corpus (150 files, ~3.2 MB) |
| `files/MANIFEST.tsv` | one line per file: arch, name, technique, seed, size, the change made |
| `probe/probe.rs` | the in-container probe that execs one file and classifies the outcome |
| `run_oracle.sh` | runs every file in a locked-down container and writes `verdicts.tsv` |
| `binfmt_misc.txt` | snapshot of the host kernel's binfmt_misc handlers, used to tell kernel from emulator |
| `verdicts.tsv` | the verdicts, with provenance |
| `API_PROPOSAL.md` | the diagnostics API proposal (now realized in `unforge-elf`; see its status note) that `tests/tolerant_api.rs` tests |

## How the files are made

```sh
cargo run -p unforge-testgen -- generate      # rewrites files/ and files/MANIFEST.tsv
```

`crates/unforge-testgen` (not published) has its own ELF64 editor and does not
use `unforge-elf`, so the corpus does not share code with the reader it
tests. Output depends only on the committed seed bytes (checked: two runs give
identical sha256 for all 150 files).

- **Seeds.** `seeds/marker.rs` is a std Rust program: write `UNFORGE_OK\n`,
  `exit(42)`. `seeds/build.sh` builds it as a static musl executable for
  aarch64 (`ET_EXEC`, 36 KB) and x86_64 (`ET_EXEC`, 25 KB), plus an x86_64
  static PIE (`ET_DYN` with `PT_DYNAMIC`, 28 KB), linked by rust-lld,
  opt-level `s`, stripped. std is rebuilt on nightly with
  `panic = "immediate-abort"` (`-Z build-std`), because the prebuilt std makes
  the same program ~330 KB, which would push the corpus past 20 MB. The
  aarch64 musl target does not produce a static PIE, so the `d*` files exist
  for x86_64 only.
- **`s*`**: edits of the static seed. **`y*`**: the static seed plus a
  synthesized `.symtab`/`.strtab` (32 `STT_FUNC` + 1 `STT_OBJECT`), then
  edited. **`d*`**: edits of the x86_64 static PIE. **`t*`**: built byte by
  byte (`crates/unforge-testgen/src/tiny.rs`): a 64-byte header, program
  headers and 47 bytes of code that `write(1, "UNFORGE_OK\n", 11)` and
  `exit(42)`, position-independent so the same code works for `ET_DYN`.
  `t84`-`t86` and `t89` name glibc's `ld.so` from the oracle image in
  `PT_INTERP` and carry a 5-entry `PT_DYNAMIC`.
- Names match TECHNIQUES.md where the same change is described there. The
  bytes differ from the files that document ran (other seeds), so the
  verdicts can differ too: see "Differences from TECHNIQUES.md" below.

## How the verdicts were produced

`run_oracle.sh` (2026-11-16, Docker Desktop 29.7.2 on macOS aarch64):

1. Builds `probe/probe.rs` as a static musl executable for aarch64 and
   x86_64, builds the generator and regenerates the corpus.
2. Dumps `/proc/sys/fs/binfmt_misc` from a privileged container into
   `binfmt_misc.txt`. No test file is mounted into that container.
3. Runs each file in its own container, never on the host:

   ```
   docker run --rm --platform <linux/arm64|linux/amd64> --network none --read-only
     --cap-drop ALL --security-opt no-new-privileges --pids-limit 16
     --memory 64m --memory-swap 64m --cpus 1 --ulimit core=0 --ulimit nofile=64
     --user 65534:65534 -v probe:/oracle/probe:ro -v <file>:/oracle/target:ro
     debian@sha256:<platform manifest digest> sh -c 'uname -r; uname -m; exec /oracle/probe /oracle/target 3000'
   ```

   plus a 30 s watchdog that `docker kill`s the container. The image is
   `debian:bookworm-slim`, pinned per platform by manifest digest (index
   `sha256:734a72b3…`); it supplies `sh`, `uname` and glibc's `ld.so` for the
   `PT_INTERP` files.
4. The probe starts the file with `std::process::Command` (absolute path, no
   shell, no `PATH` search, empty environment) and prints a verdict:

| verdict | meaning |
|---|---|
| `exec_rejected:<ERRNO>` | `spawn()` failed: `execve` returned the errno. Only possible before the point of no return, so the loader refused the file. |
| `ran` | exit 42 and `UNFORGE_OK` on stdout: the entry code ran. |
| `loaded_then_signal:<SIG>` | killed by a signal after the marker, or by a signal other than SIGSEGV/SIGKILL. The exec abort path only raises SIGSEGV (below), so these were loaded. |
| `loaded_then_exit:<code>` | any other exit. |
| `ldso_rejected` | exit 127 with a glibc/musl dynamic-loader message on stderr. |
| `ambiguous:<SIG>` | SIGSEGV or SIGKILL with no marker. |
| `timeout` | still running after 3 s; killed. |

### The point of no return, and why `ambiguous` exists

`load_elf_binary` calls `begin_new_exec()` (`fs/binfmt_elf.c` v7.0.12 line
1011), which sets `bprm->point_of_no_return` (`fs/exec.c` line 1112). Every
error after that, for example a `PT_LOAD` with `p_filesz > p_memsz`
(`fs/binfmt_elf.c` line 1227-1232), a file offset not congruent to the address
(`vm_mmap` -> `-EINVAL`), or `padzero()` failing on a writable segment
(`elf_load`, line 436-437), cannot be returned to the caller: the old image is
gone. `bprm_execve` then calls `force_fatal_sig(SIGSEGV)` unless a fatal signal
is already pending (`fs/exec.c` lines 1768-1769). From the parent this looks
exactly like a program that crashed on its first instruction. So a SIGSEGV (or
SIGKILL) without the marker is recorded as `ambiguous`, never as "loaded".
Observed examples: `t74` (`p_filesz > p_memsz`), `t82` (offset/address not
congruent) and `t62` (writable segment past EOF) are kernel aborts by the
rules above, while `t78` (entry unmapped), `t79` (entry not executable) and
`t80` (no `PT_LOAD`) are loaded files that fault at the entry. All six are
`ambiguous` in `verdicts.tsv`; the probe alone cannot tell them apart. The
hand-made files make the remaining cases unambiguous: their first instruction
prints the marker, so any `ran` or post-marker verdict proves user code ran.

### Kernel or emulator

The container uses the **host** kernel (Docker Desktop's linuxkit VM,
`7.0.12-linuxkit`, aarch64), so the image digest does not pin the kernel;
`uname -r` and `uname -m` are recorded on every row (`uname_r` column,
`uname_m=` at the start of `detail`) and in the header.

- `source = kernel`: an aarch64 file in a `linux/arm64` container that no
  binfmt_misc entry matches. Only these went through `fs/binfmt_elf.c`.
- `source = emulator:<entries>`: binfmt_misc matched the file (its magic and
  mask, see `binfmt_misc.txt`), so the kernel handed it to the named
  interpreter (`rosetta`, `rosetta-wrapper` and `x86_64`/qemu all claim
  x86-64 ELF; which one ran is decided by registration order, not recorded;
  the probe saw `/run/rosetta/rosetta` mapped, `probe_under=rosetta`). Every
  x86_64 row is an emulator row: in a `linux/amd64` container even the probe
  is emulated.
- `source = emulator:unmatched`: an x86_64 file no handler claims (the x86-64
  masks require `EI_CLASS = 2`, `EI_DATA` 0/1, zero padding). The aarch64
  kernel then refuses it or runs it as aarch64 code. Not a verdict about any
  x86-64 kernel.

Emulator verdicts are **not authoritative**, and this corpus shows why:

- Rosetta ran `s31` (`e_phentsize = 32`), `t74` (`p_filesz > p_memsz`) and
  `t62`, which the kernel refuses or aborts.
- Rosetta refuses `t71`-`t73`, `t75`-`t77`, `t80`-`t82`, `t89` by raising
  **SIGTRAP**, so an emulator refusal looks like `loaded_then_signal:SIGTRAP`.
- binfmt_misc masks are stricter than the kernel: `s16`-`s18`, `s21`, `d16`,
  `d18`, `d21`, `t61` (`EI_*` garbage the kernel ignores) are not claimed, and
  the aarch64 kernel returns `ENOEXEC`.
- An aarch64 file with `e_machine = EM_X86_64` (`aarch64/s32`) is claimed by
  the x86-64 handler and crashes in the emulator; a native arm64 kernel
  without that handler returns `ENOEXEC` from `elf_check_arch` (source, not
  run).

`crates/unforge-elf/tests/kernel_oracle.rs` refuses `verdicts.tsv` if any
`source = kernel` row has a `uname_r` other than the header's
`kernel_uname_r`, or an arch other than `kernel_uname_m`, or if a source is
neither `kernel` nor `emulator:*`. Emulator rows are checked but only
reported.

## Results

48 aarch64 files were loaded by the kernel (`ran` 47, `loaded_then_signal`
1), 12 were refused at exec, 8 are ambiguous, and 1 went to the emulator.
x86_64: 81 emulator rows. Per file:

| file | technique | change | aarch64 verdict (kernel) | x86_64 verdict (emulator) |
|---|---|---|---|---|
| `s00-baseline` | control | the seed, unchanged | ran | ran |
| `s01-shdr-zeroed` | T01 | e_shoff, e_shnum, e_shstrndx = 0 (table bytes kept) | ran | ran |
| `s02-sstrip` | T01 | ELFkickers sstrip: cut after the last byte a program header uses, section fields zeroed | ran | ran |
| `s03-shoff-garbage` | T02 | e_shoff = 0xdeadbeefdeadbeef | ran | ran |
| `s04-shoff-past-eof` | T02 | e_shoff = file size + 0x1000 | ran | ran |
| `s05-shnum-ffff` | T03 | e_shnum = 0xffff (table runs past EOF) | ran | ran |
| `s06-shentsize-1` | T04 | e_shentsize = 1 | ran | ran |
| `s07-shstrndx-out-of-range` | T05 | e_shstrndx = 0x1234 | ran | ran |
| `s08-shstrndx-is-text` | T05 | e_shstrndx = index of .text (names read from code) | ran | ran |
| `s09-text-size-huge` | T06 | .text sh_size = 0xffffffffffff | ran | ran |
| `s10-rodata-offset-past-eof` | T06 | .rodata sh_offset = file size + 0x100 | ran | ran |
| `s11-decoy-swap-text-rodata-names` | T07 | sh_name of .text and .rodata swapped | ran | ran |
| `s12-text-is-nobits` | T07 | .text sh_type = SHT_NOBITS | ran | ran |
| `s13-progbits-all-overlap-text` | T08 | every other SHT_PROGBITS section covers exactly the .text bytes | ran | ran |
| `s14-2000-symtabs-same-bytes` | T08 | new section table at EOF: original entries + 2000 SHT_SYMTAB over the .text bytes | ran | ran |
| `s15-section-addr-disagree-with-segments` | T09 | sh_addr += 0x100000 for every section with a non-zero address | ran | ran |
| `s16-ei-class-32` | T12 | EI_CLASS = 1 (claims ELF32) | ran | exec_rejected:ENOEXEC (unmatched) |
| `s17-ei-class-0x55` | T12 | EI_CLASS = 0x55 (invalid) | ran | exec_rejected:ENOEXEC (unmatched) |
| `s18-ei-data-be` | T12 | EI_DATA = 2 (claims big-endian) | ran | exec_rejected:ENOEXEC (unmatched) |
| `s19-ei-data-0` | T12 | EI_DATA = 0 (ELFDATANONE) | ran | ran |
| `s20-ei-version-0-e_version-0` | T12 | EI_VERSION = 0 and e_version = 0 | ran | ran |
| `s21-osabi-freebsd-pad-garbage` | T12 | EI_OSABI = 9, EI_ABIVERSION = 0x42, EI_PAD = "GARBAGE" | ran | exec_rejected:ENOEXEC (unmatched) |
| `s22-ehsize-0` | T13 | e_ehsize = 0 | ran | ran |
| `s23-ehsize-ffff` | T13 | e_ehsize = 0xffff | ran | ran |
| `s24-phdr-outside-every-load` | T11 | program header table copied to EOF (no PT_LOAD covers it), e_phoff points at the copy | ambiguous:SIGSEGV | ran |
| `s25-truncated-inside-last-load` | T14 | file cut 0x10 bytes into the last PT_LOAD (writable, p_memsz > p_filesz) | ran | ran |
| `s26-last-load-filesz-past-eof` | T14 | after sstrip, last PT_LOAD p_filesz = p_memsz = old p_memsz + 0x10000 | ran | loaded_then_signal:SIGBUS |
| `s27-ptload-duplicate-of-rx` | T15 | the PT_GNU_EH_FRAME slot becomes a copy of the R-X PT_LOAD | ran | ran |
| `s28-ptload-later-overrides-text` | T15 | the PT_GNU_EH_FRAME slot becomes a PT_LOAD mapping file page 0 over the first page of the R-X segment | loaded_then_signal:SIGILL | ambiguous:SIGSEGV |
| `s29-ptload-not-sorted` | T15 | first and last PT_LOAD entries swapped | ran | loaded_then_signal:SIGTRAP |
| `s30-palign-not-power-of-two` | T15 | p_align = 3 on every PT_LOAD | ran | ran |
| `s31-phentsize-wrong` | T19 | e_phentsize = 32 (control: the kernel refuses) | exec_rejected:ENOEXEC | ran |
| `s32-machine-wrong` | T19 | e_machine set to the other architecture (control) | ambiguous:SIGSEGV (**emulator:rosetta\|rosetta-wrapper\|x86_64**) | loaded_then_signal:SIGILL (unmatched) |
| `s33-e_flags-garbage` | T12 | e_flags = 0xdeadbeef (native kernels do not read it) | ran | ran |
| `s34-unknown-ptype` | T15 | the PT_GNU_EH_FRAME slot gets p_type 0x12345678 | ran | ran |
| `s35-palign-incongruent` | T15 | p_align = 0x100000 on every PT_LOAD, so the gABI p_offset % p_align == p_vaddr % p_align rule fails (page congruence still holds) | ran | ran |
| `y00-symtab-baseline` | control | static seed + synthesized .symtab/.strtab (33 symbols) | ran | ran |
| `y50-symtab-st_name-out-of-range` | T17 | every st_name = 0xffffff00 + k | ran | ran |
| `y51-symtab-sh_link-to-text` | T17 | .symtab sh_link = index of .text | ran | ran |
| `y52-symtab-entsize-0-size-ragged` | T17 | .symtab sh_entsize = 0, sh_size += 7 | ran | ran |
| `y53-symtab-funcs-all-same-addr-huge-size` | T17 | every STT_FUNC gets the first one's st_value and st_size = 0xffffffffffff | ran | ran |
| `y54-symtab-st_shndx-garbage` | T17 | every st_shndx = 0xfeee (reserved range) | ran | ran |
| `t60-tiny-phdr-overlaps-ehdr` | T10 | e_phoff = 0x38: the PT_LOAD entry overlaps e_phnum..e_shstrndx; code at 0x70 | ran | ran |
| `t61-tiny-overlap-all-unused-fields-garbage` | T10 | t60 with garbage in EI_CLASS..EI_PAD, e_version, e_shoff, e_flags, e_ehsize | ran | exec_rejected:ENOEXEC (unmatched) |
| `t62-rwx-filesz-past-eof-memsz-bigger` | T14 | overlapped tiny, single RWX PT_LOAD p_filesz = 0x1100 (file is smaller), p_memsz = 0x3000 | ambiguous:SIGSEGV | ran |
| `t63-rx-filesz-past-eof-memsz-bigger` | T14 | as t62 but R-X | ran | ran |
| `t64-rx-filesz-past-eof` | T14 | as t63 but p_memsz = p_filesz = 0x1100 | ran | ran |
| `t65-control-tiny` | control | hand-made, no overlap: ELF header, one PT_LOAD at 0x40, code at 0x120 | ran | ran |
| `t70-e_type-rel` | T19 | e_type = ET_REL (control) | exec_rejected:ENOEXEC | exec_rejected:ENOEXEC (unmatched) |
| `t71-e_phnum-0` | T19 | e_phnum = 0 (control) | exec_rejected:ENOEXEC | loaded_then_signal:SIGTRAP |
| `t72-e_phnum-1171` | T19 | e_phnum = 1171, so e_phnum * 56 > 65536 (control) | exec_rejected:ENOEXEC | loaded_then_signal:SIGTRAP |
| `t73-phdr-table-past-eof` | T19 | e_phoff points 0x10 bytes before EOF (control) | exec_rejected:ENOEXEC | loaded_then_signal:SIGTRAP |
| `t74-filesz-gt-memsz` | T19 | PT_LOAD p_filesz = 0x210 > p_memsz = 0x100 (control, post point of no return) | ambiguous:SIGSEGV | ran |
| `t75-interp-filesz-1` | T19 | PT_INTERP p_filesz = 1 (control) | exec_rejected:ENOEXEC | loaded_then_signal:SIGTRAP |
| `t76-interp-not-nul-terminated` | T19 | PT_INTERP "/nonexistent" without its NUL (control) | exec_rejected:ENOEXEC | loaded_then_signal:SIGTRAP |
| `t77-interp-missing-file` | T19 | PT_INTERP "/nonexistent/ld.so" (control) | exec_rejected:ENOENT | loaded_then_signal:SIGTRAP |
| `t78-entry-unmapped` | T19 | e_entry = 0x10000, outside every PT_LOAD | ambiguous:SIGSEGV | ambiguous:SIGSEGV |
| `t79-entry-in-non-exec-load` | T19 | the only PT_LOAD is R only | ambiguous:SIGSEGV | ambiguous:SIGSEGV |
| `t80-no-pt-load` | T19 | ET_EXEC whose only program header is PT_NULL | ambiguous:SIGSEGV | loaded_then_signal:SIGTRAP |
| `t81-phnum-pn-xnum` | T19 | e_phnum = PN_XNUM (0xffff) with section 0 sh_info = 1 (gABI escape; control) | exec_rejected:ENOEXEC | loaded_then_signal:SIGTRAP |
| `t82-offset-vaddr-not-congruent` | T19 | PT_LOAD p_offset = 0 but p_vaddr = BASE + 0x10 (not congruent mod page; post point of no return) | ambiguous:SIGSEGV | loaded_then_signal:SIGTRAP |
| `t83-et-dyn-tiny` | control | ET_DYN, PT_LOAD at p_vaddr 0 (position-independent tiny PIE) | ran | ran |
| `t84-interp-ldso-minimal-dynamic` | T16 | PT_INTERP = glibc ld.so, PT_DYNAMIC with DT_STRTAB/DT_SYMTAB/DT_STRSZ/DT_SYMENT only | ran | ran |
| `t85-interp-ldso-pt_dynamic-offset-garbage` | T16 | t84 with PT_DYNAMIC p_offset = 0xdeadbeef, p_filesz = 0xffffffff | ran | ran |
| `t86-interp-ldso-no-pt_dynamic` | T16 | t84 with PT_DYNAMIC turned into PT_NULL | ambiguous:SIGSEGV | ambiguous:SIGSEGV |
| `t87-phentsize-64` | T19 | e_phentsize = 64 (larger than Elf64_Phdr; control) | exec_rejected:ENOEXEC | ran |
| `t88-gnu-property-bad-note-name` | T19 | PT_GNU_PROPERTY note named "XYZ" (arm64 parses it, x86-64 v7.0.12 does not) | exec_rejected:ENOEXEC | ran |
| `t89-two-interp-first-wins` | T19 | first PT_INTERP names a missing file, the second names glibc ld.so (the kernel uses the first) | exec_rejected:ENOENT | loaded_then_signal:SIGTRAP |
| `t90-phdr-not-in-load-no-ldso` | T11 | program header table at EOF outside the PT_LOAD; code does not read AT_PHDR | ran | ran |
| `d00-baseline` | control | the static-PIE seed, unchanged | – | ran |
| `d01-shdr-zeroed` | T01 | section header fields zeroed | – | ran |
| `d02-sstrip` | T01 | ELFkickers sstrip | – | ran |
| `d16-ei-class-32` | T12 | EI_CLASS = 1 | – | exec_rejected:ENOEXEC (unmatched) |
| `d18-ei-data-be` | T12 | EI_DATA = 2 | – | exec_rejected:ENOEXEC (unmatched) |
| `d21-osabi-freebsd-pad-garbage` | T12 | EI_OSABI = 9, EI_ABIVERSION = 0x42, EI_PAD garbage | – | exec_rejected:ENOEXEC (unmatched) |
| `d40-pt_dynamic-offset-filesz-garbage` | T16 | PT_DYNAMIC p_offset = 0xdeadbeef, p_filesz = 0xffffffff (p_vaddr kept) | – | ran |
| `d41-pt_dynamic-vaddr-into-rodata` | T16 | PT_DYNAMIC p_vaddr = .rodata sh_addr | – | ambiguous:SIGSEGV |
| `d42-dynamic-section-header-garbage` | T06 | .dynamic sh_offset = 0xdeadbeef, sh_size = 0x7fffffff | – | ran |
| `d43-dynsym-sh_link-to-shstrtab` | T17 | .dynsym sh_link = index of .shstrtab | – | ran |
| `d44-dynsym-section-points-at-text` | T07 | .dynsym sh_offset = .text sh_offset | – | ran |
| `d46-pt_dynamic-removed` | T16 | PT_DYNAMIC turned into PT_NULL | – | ambiguous:SIGSEGV |

### Differences from TECHNIQUES.md

TECHNIQUES.md §4 ran the same changes on other binaries
(`testdata/bin/.../panics-*`, Debian's `/bin/true`). Two verdicts differ here
and both follow from the rules:

- `s25` (truncated 0x10 bytes into the last `PT_LOAD`) **runs** here; it died
  with SIGSEGV there. `padzero()` writes to the page that holds
  `p_offset + p_filesz`. In this seed that page starts at file offset 0x8000,
  inside the 0x8680-byte file, so the write succeeds; in TECHNIQUES.md's base
  it did not.
- `s26` (last `PT_LOAD` claims 64 KiB past EOF) **runs** on aarch64 here; it
  died with SIGBUS there. The marker program never touches the pages that
  are wholly past EOF. (Under Rosetta, x86_64 `s26` gets SIGBUS.)
- New data points not in TECHNIQUES.md: `t90` (program headers outside every
  `PT_LOAD`, code that does not read `AT_PHDR`) **runs**, confirming the
  T11 note that only `AT_PHDR` readers crash; `t85` (`PT_DYNAMIC` `p_offset`
  garbage) runs under glibc ld.so on aarch64, as T16 predicts; `t88`
  (malformed `PT_GNU_PROPERTY` note) is refused with `ENOEXEC` on arm64, the
  one place where the kernel is stricter than ld.so (LOADER_RULES.md).

## Tests and current status

```sh
cargo test -p unforge-elf --test kernel_oracle
cargo test -p unforge-elf --test tolerant_api
```

`kernel_oracle.rs`, for every `source = kernel` file the kernel loaded: `parse`
succeeds; the header fields the loader uses (`e_type`, `e_machine`,
`e_entry`, `e_phoff`, `e_phnum`) and the program headers equal an
independent decoding with the kernel's native ELF64-LE layout; every
`PT_LOAD`'s file bytes are returned (clipped at EOF only, which the kernel
tolerated for that file); the entry lies in an executable `PT_LOAD` under the
"later mapping wins" rule; the first `PT_INTERP` is readable; section/symbol
accessors may fail but not panic. Every file, including refused ones, must be
read without panic.

Status before the tolerant reader (2026-11-16): 5 tests passed;
`kernel_accepted_files_satisfy_tolerant_reader_invariants` failed on 9 of 48
files (layout taken from `EI_CLASS`/`EI_DATA`: `s16`, `s17`, `s18`, `s19`,
`t61`; `segment_data` refusing a `PT_LOAD` past EOF: `s25`, `s26`, `t63`,
`t64`).

Status with the tolerant reader (same day): all 6 `kernel_oracle` tests and
all 27 `tolerant_api` tests pass. The layout is chosen from `e_machine` and
the header sizes (`unforge-elf` `src/layout.rs`), segments are clipped at
EOF, and `ElfFile::kernel_prediction_for` agrees with every `source = kernel`
verdict.

## Not verified

- The arm64 kernel's page size in linuxkit was not read from its config; the
  padzero consistency check in `kernel_oracle.rs` assumes 4 KiB and only
  logs a note when it disagrees.
- Which of the three x86-64 binfmt_misc handlers ran a given file.
- The classification of each `ambiguous` file as "kernel abort" or "fault at
  entry" above is from source (LOADER_RULES.md), not observed.
- x86-64 kernel verdicts: none exist here. Every x86_64 row is from an
  emulator.

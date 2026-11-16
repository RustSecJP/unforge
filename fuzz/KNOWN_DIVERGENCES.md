# Known divergences: unforge-elf vs object / goblin

`fuzz_targets/differential.rs` parses every input with `unforge-elf`,
`object` 0.41.0 (low-level `object::read::elf` API) and `goblin` 0.10.7
(`goblin::elf::Elf::parse`, strict mode), and compares the ELF header, the
program headers, the section headers, the section names and the symbols
wherever an oracle succeeds.

- An oracle failing is never a divergence (`unforge-elf` is meant to be more
  tolerant than both).
- `unforge-elf` failing where an oracle succeeds, or a value that differs, is
  a divergence. It aborts the run unless it is one of the entries below.
- Each entry names the `unforge-elf` diagnostic(s) (`DiagnosticKind::name()`)
  that must be in `ElfFile::audit()` when it is hit. If none of them is
  there, the run aborts with `SILENT known divergence`: a tolerant reading is
  only acceptable when it is reported. "none required" means the entry is a
  difference in the oracle's own reading, not something `unforge-elf` infers.
- When `unforge-elf` reads a layout other than the one `EI_CLASS`/`EI_DATA`
  claim (KD-01), nothing else is compared: the oracles read different bytes.

Oracle source references are to the crate sources in the Cargo registry
(`object-0.41.0/src/read/elf/...`, `goblin-0.10.7/src/...`). Kernel
references are to Linux v7.0.12 as recorded in
`testdata/anomalous/LOADER_RULES.md`.

Running the target:

```sh
cargo +nightly fuzz run differential corpus/differential -- -max_len=262144
# triage a directory: print every divergence instead of aborting, one line
# per input with the comparisons that ran and the entries that were hit
UNFORGE_DIFF_REPORT=1 UNFORGE_DIFF_LOG=1 \
  ./target/<host>/release/differential -runs=1 <files...>
```

## Allowlist

### KD-01-layout-inferred
- **Divergence:** `EI_CLASS`/`EI_DATA` are valid but `unforge-elf` reads the
  file in another layout (chosen from `e_machine` and the header size
  fields). `object` and `goblin` read the claimed layout.
- **Justification:** the kernel never reads `EI_CLASS` or `EI_DATA`: the
  layout is fixed by the handler (`fs/binfmt_elf.c` `load_elf_binary`, native
  class; `fs/compat_binfmt_elf.c` ELFCLASS32), chosen by `elf_check_arch` on
  `e_machine` (LOADER_RULES.md §1). The bytes are clues, not facts.
- **Required diagnostic:** `class-mismatch` or `data-mismatch` (each carries
  the claimed value; the layout `Inference` lists the clues and candidates).

### KD-02-phoff-zero
- **Divergence:** `e_phoff == 0` with `e_phnum != 0`. `object` returns no
  program headers without looking at `e_phnum`
  (`read/elf/file.rs` `program_headers`, `if phoff == 0`, line 732);
  `unforge-elf` (and `goblin`) read the table at file offset 0, or report it
  unreadable (e.g. `PN_XNUM` with no section 0).
- **Justification:** the kernel reads `e_phnum * sizeof(phdr)` bytes at
  `e_phoff` with no special case for 0 (`load_elf_phdrs`, `elf_read`;
  LOADER_RULES.md §1 row `e_phoff`). The gABI gives 0 the meaning "no table"
  for `e_phoff` ("If the file has no program header table, this member holds
  zero"), but a nonzero `e_phnum` contradicts that and the loader follows
  `e_phnum`.
- **Required diagnostic:** none required. `phdrs-overlap-header` is emitted
  when the table is read (offset 0 is inside `sizeof(Ehdr)`),
  `phdrs-unreadable` when it is not; neither is an inference.

### KD-03a-phentsize-not-struct-size / KD-03b-shentsize-not-struct-size
- **Divergence:** `e_phentsize` (resp. `e_shentsize`) larger than
  `sizeof(Phdr)` (resp. `sizeof(Shdr)`). `goblin` ignores the field and reads
  entries `sizeof` apart (`elf/program_header.rs` `parse`, lines 162-174;
  `elf/section_header.rs` `parse_from`, lines 458-479); `unforge-elf` uses
  the field as the stride and reads the first `sizeof` bytes of each entry.
  (`object` refuses any other value: `file.rs` lines 653, 742, 770.)
- **Justification:** gABI ch4 "ELF Header": `e_phentsize` / `e_shentsize`
  "holds the size in bytes of one entry in the ... table; all entries are the
  same size". musl's `ldso/dynlink.c` uses `e_phentsize` as the stride
  without comparing it to `sizeof(Phdr)` (LOADER_RULES.md, musl table). The
  kernel and glibc reject `e_phentsize != sizeof` (`load_elf_phdrs`;
  `dl-load.c` 1741-1745), which the kernel prediction reports separately.
- **Required diagnostic:** `bad-phentsize` (resp. `bad-shentsize`).

### KD-03c-sym-entsize-not-struct-size
- **Divergence:** a symbol table whose `sh_entsize` is not `sizeof(Sym)`.
  `object` ignores `sh_entsize` and reads `sh_size / sizeof(Sym)` packed
  entries (`section.rs` `data_as_array`, line 780; used by
  `SymbolTable::parse`). `goblin` takes the count as `sh_size / sh_entsize`
  (0 when `sh_entsize == 0`) but reads entries `sizeof(Sym)` apart
  (`elf/mod.rs` lines 316-318, `elf/sym.rs` `Symtab::parse`). `unforge-elf`
  uses `max(sh_entsize, sizeof(Sym))` as the stride and `sh_size / stride` as
  the count.
- **Justification:** gABI ch4 "Sections", `sh_entsize`: "Some sections hold
  a table of fixed-size entries, such as a symbol table. For such a section,
  this member gives the size in bytes of each entry." A smaller value cannot
  hold a symbol, so `sizeof(Sym)` is inferred.
- **Required diagnostic:** `symbol-entry-size` (plus an
  `inferred-symbol-entry-size` inference when the stride was replaced).
  Duplicate tables currently break this requirement: see R-2.

### KD-04-pn-xnum
- **Divergence:** `e_phnum == PN_XNUM` (0xffff). `goblin` reads 65535
  program headers (`elf/mod.rs` line 279 passes the raw `e_phnum`);
  `unforge-elf` and `object` take the count from section 0's `sh_info`.
- **Justification:** gABI ch4 "ELF Header", `e_phnum`: "If the number of
  program headers is greater than or equal to PN_XNUM (0xffff), this member
  has the value PN_XNUM (0xffff). The actual number of program header table
  entries is contained in the sh_info field of the section header at index
  0." The kernel does not implement this escape (it uses `e_phnum`
  literally and then rejects 65535 entries as too large, `load_elf_phdrs`
  537-539), so no loaded interpretation exists either way.
- **Required diagnostic:** none required (a gABI rule, not an inference).
- **Hits:** 0 in this run (goblin's `count > bytes.len() / sizeof` check
  rejects 65535 entries in any input below ~3.6 MiB). Kept from source
  reading.

### KD-05-shnum-without-table
- **Divergence:** `e_shoff == 0` but `e_shnum != 0`. `object`'s `shnum()`
  returns `e_shnum` (`file.rs` `shnum`); `unforge-elf` reports 0 sections.
- **Justification:** gABI ch4 "ELF Header", `e_shoff`: "If the file has no
  section header table, this member holds zero." Offset 0 holds the ELF
  header, so no table can be there. (`object`'s `section_headers()` also
  returns an empty table here; only the count disagrees.)
- **Required diagnostic:** `shnum-without-table`.

### KD-06-strtab-is-null-or-nobits
- **Divergence:** the section name table (`e_shstrndx`) or a symbol table's
  `sh_link` names an `SHT_NULL` or `SHT_NOBITS` section. `object` reads an
  `SHT_NULL` section's file bytes (`section.rs` `file_range`, line 750,
  special-cases only `SHT_NOBITS`); `goblin` reads the bytes of both
  (`elf/mod.rs` `get_strtab`, lines 293-307, no type check). `unforge-elf`
  gives such a section no file bytes, so names in it are unreadable.
- **Justification:** gABI ch4 "Sections": `SHT_NULL` "marks the section
  header as inactive; it does not have an associated section. Other members
  of the section header have undefined values." `SHT_NOBITS` "occupies no
  space in the file".
- **Required diagnostic:** `shstrndx-not-strtab` or `symbol-link-not-strtab`
  (both come with a string table inference listing the alternatives).

### KD-07-goblin-extended-shnum-zero
- **Divergence:** `e_shnum == 0`, `e_shoff != 0` and section 0's `sh_size ==
  0`. `goblin` returns one section header (section 0); `unforge-elf` and
  `object` return none.
- **Justification:** gABI ch4 "ELF Header", `e_shnum`: when the count does
  not fit, `e_shnum` is 0 "and the actual number of section header table
  entries is contained in the sh_size field of the section header at index 0
  (otherwise, the sh_size member of the initial entry contains 0)". The count
  read from there is 0. `goblin` pushes section 0 before applying the count
  (`elf/section_header.rs` `parse_from`, lines 460-477). Oracle quirk.
- **Required diagnostic:** none required.

### KD-08-goblin-section0-as-strtab
- **Divergence:** `e_shstrndx == 0` or a symbol table's `sh_link == 0`.
  `goblin` uses section 0's `sh_offset`/`sh_size` as the string table
  (`elf/mod.rs` `get_strtab`, only `section_idx >= len` gives an empty
  table); `unforge-elf` has no string table.
- **Justification:** index 0 is `SHN_UNDEF`. gABI ch4 "ELF Header",
  `e_shstrndx`: "If the file has no section name string table, this member
  holds the value SHN_UNDEF." Section 0's other fields are undefined or hold
  the extended numbering values. Oracle quirk.
- **Required diagnostic:** none required for `e_shstrndx == 0` (a legitimate
  "no names" file); `symbol-link-invalid` is emitted for `sh_link == 0`.

### KD-09-several-symtab-shndx
- **Divergence:** more than one `SHT_SYMTAB_SHNDX` section links to the same
  symbol table, and a symbol uses `SHN_XINDEX`. `object` uses the last one
  (`symbol.rs` `SymbolTable::parse`, loop at line 72-79 overwrites);
  `unforge-elf` the first.
- **Justification:** the gABI defines one such section per symbol table and
  says nothing about several, so neither reading is specified.
- **Required diagnostic:** `inferred-extended-index-table` (the audit
  records which section was used and lists the others as alternatives).
- **Hits:** 0 in this run. Kept from source reading.

### KD-10-shstrndx-xindex-link-0
- **Divergence:** `e_shstrndx == SHN_XINDEX` and section 0's `sh_link == 0`.
  `object` resolves the index to 0 and reads names from section 0
  (`file.rs` `shstrndx` and `section_strings`); `unforge-elf` treats 0 as
  `SHN_UNDEF` and has no section names.
- **Justification:** as KD-08: index 0 is `SHN_UNDEF`, and an index below
  `SHN_LORESERVE` must not use the escape at all (gABI ch4 "ELF Header",
  `e_shstrndx`). Oracle quirk.
- **Required diagnostic:** none required.

### KD-11-unterminated-last-string
- **Divergence:** a name starts inside a string table but no NUL follows
  before the end of the table. `goblin` returns the bytes up to the end of
  the section (its `Strtab` keeps the unterminated tail as a string);
  `unforge-elf` returns `Err(BadString)` for that name.
- **Justification:** gABI ch4 "String Table": "the last byte is defined to
  hold a null character, ensuring null termination for all strings". Where
  such a string ends is unknown; returning an error rather than guessing an
  end is a defensible reading.
- **Required diagnostic:** one of `string-table-unterminated`,
  `section-names-unterminated`, `symbol-names-unterminated` (added for
  finding R-1).

## Findings in unforge-elf

Both are fixed; the tests in
`crates/unforge-elf/tests/differential_regressions.rs` embed the inputs.

### R-1: unterminated last string not reported (KD-11) — fixed
`audit()` is identical for a file whose `.shstrtab` / `.strtab` ends without
a NUL and for the same file with the NUL, although names in it become
unreadable. `SymbolNamesOutOfRange` counts only `st_name >= sh_size`, and
section names have no per-name check. Tests:
`r1_unterminated_section_name_table_is_reported`,
`r1_unterminated_symbol_string_table_is_reported` (input: 432-byte
hand-minimized ELF64 LSB, reproducing the KD-11 hits of the seed corpus).

### R-2: duplicate symbol tables skip the whole symbol audit — fixed
`audit_symbols` (`src/audit.rs`) skips every table reported as
`DuplicateTable`, i.e. with the same `sh_offset`/`sh_size` as an earlier
symbol table. The duplicate's own `sh_entsize` and `sh_link` may differ, and
`symbol_table(i)` reads it with them, so:
- `sh_entsize` larger than `sizeof(Sym)` gets no `SymbolEntrySize`;
- `sh_entsize` of 0 makes the reader infer the stride with no `Inference`
  recorded: a silent inference.

Found by the target as `SILENT known divergence KD-03c` (all 9 + 11 such
artifacts of the two fuzzing rounds are duplicate tables). Tests:
`r2_duplicate_table_with_larger_entsize_is_reported`,
`r2_duplicate_table_with_inferred_entsize_records_the_inference` (input:
artifact `crash-d25f502f...`, minimized by libFuzzer to 536 bytes).

Fixed: a duplicate table is checked on its own header (entry size, stride
inference, link, string table), and its symbols are walked again unless it
is read with the same stride and string table as the table it duplicates.

## Oracle problems seen

- No oracle panic was caught in this run (`ORACLE-goblin-panic` events: 0).
- KD-07, KD-08 and KD-10 are oracle readings that contradict the gABI (see
  each entry). They are allowlisted, not reported upstream.

## Counts (2026-11-16)

Fuzzing: two rounds of `-fork=6 -ignore_crashes=1`, 304 s and 320 s,
2,156,651 + 2,066,277 executions. Seeds: `corpus/parse` (2,917 files),
`testdata/anomalous/files` (150), ELF files under 200 KiB from
`testdata/bin` (36); 3,103 seeds, 4,311 inputs in the final corpus.

Round 1 produced 99 crash artifacts in 5 classes: 80 + 8 were missing
allowlist cases (KD-02 with `PN_XNUM`, KD-10 for names), fixed in the
target; 11 were R-2. Round 2, with the fixed target, produced 11 artifacts,
all R-2.

Replay of the final corpus (4,311 inputs; 46 are rejected by
`ElfFile::parse` and by both oracles; no new divergence):

| comparison | inputs |
|---|---|
| object: header read | 4,090 |
| object: program headers | 2,268 |
| object: section headers | 1,866 |
| object: section names | 1,173 |
| object: symbol tables | 443 |
| goblin: `Elf::parse` succeeded | 793 |
| goblin: section names | 686 |
| goblin: `.symtab` | 269 |

| entry | inputs hitting it |
|---|---|
| KD-01-layout-inferred | 67 |
| KD-02-phoff-zero | 274 |
| KD-03a-phentsize-not-struct-size | 122 |
| KD-03b-shentsize-not-struct-size | 80 |
| KD-03c-sym-entsize-not-struct-size | 163 |
| KD-04-pn-xnum | 0 |
| KD-05-shnum-without-table | 44 |
| KD-06-strtab-is-null-or-nobits | 131 |
| KD-07-goblin-extended-shnum-zero | 27 |
| KD-08-goblin-section0-as-strtab | 20 |
| KD-09-several-symtab-shndx | 0 |
| KD-10-shstrndx-xindex-link-0 | 12 |
| KD-11-unterminated-last-string | 46 |

## Not compared

- Files read in an inferred layout (KD-01): only header acceptance.
- Dynamic table, relocations, notes, versions: not compared.
- At most 4,096 sections and 65,536 symbols per input.
- `goblin` is compared only through `Elf::parse` in strict mode, so a file
  that `goblin` rejects for an unrelated reason (relocations, dynamic
  section) is not compared with `goblin` at all.

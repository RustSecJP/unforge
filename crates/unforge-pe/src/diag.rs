//! Diagnostics: what the reader found odd.
//!
//! The reader never refuses a file it can find a PE header in. Every
//! anomaly (a truncated table, a section past the end of the file, an entry
//! point outside the code, a directory pointing nowhere) is described by a
//! [`Diagnostic`] instead. Plain accessors stay quiet;
//! [`crate::PeFile::diagnostics`] walks the headers and every directory once
//! and returns everything it found.

use core::fmt;

/// How bad a finding is. Ordered: `Info < Warning < WouldNotLoad`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// Unusual but harmless, or a note about the reading.
    Info,
    /// The file departs from the PE format, or a value had to be clipped or
    /// guessed: analysis results may mislead.
    Warning,
    /// The Windows loader would refuse this image or fail on this part.
    WouldNotLoad,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "note",
            Severity::Warning => "warning",
            Severity::WouldNotLoad => "would not load",
        })
    }
}

/// What a diagnostic is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Category {
    /// The bytes themselves: header fields, table bounds.
    Format,
    /// Two parts of the file disagree (header sizes vs sections, ...).
    Consistency,
    /// What the Windows loader would do with it.
    Loader,
}

/// The kind of a finding. [`DiagnosticKind::name`] is stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DiagnosticKind {
    OptionalHeaderMissing,
    OptionalHeaderTruncated,
    BadOptionalMagic,
    FewDataDirectories,
    ManyDataDirectories,
    UnknownMachine,
    NotExecutableImage,
    SectionTableTruncated,
    ManySections,
    BadAlignment,
    LowAlignment,
    SectionPastEndOfFile,
    SectionsOverlap,
    SectionMisordered,
    SizeOfImageMismatch,
    SizeOfHeadersMismatch,
    EntryOutsideImage,
    EntryNotExecutable,
    Overlay,
    DirectoryUnmapped,
    ImportsTruncated,
    ImportNameBad,
    ExportsTruncated,
    ExportNameBad,
    RelocationsTruncated,
    RelocationUnknownType,
    ExceptionTableTruncated,
    ExceptionEntryBad,
    TlsTruncated,
    TlsCallbackOutside,
    DebugDirectoryTruncated,
    CodeViewBad,
    SymbolTableTruncated,
    OutputCapped,
}

impl DiagnosticKind {
    /// A stable short name (`snake_case`).
    pub fn name(self) -> &'static str {
        use DiagnosticKind::*;
        match self {
            OptionalHeaderMissing => "optional_header_missing",
            OptionalHeaderTruncated => "optional_header_truncated",
            BadOptionalMagic => "bad_optional_magic",
            FewDataDirectories => "few_data_directories",
            ManyDataDirectories => "many_data_directories",
            UnknownMachine => "unknown_machine",
            NotExecutableImage => "not_executable_image",
            SectionTableTruncated => "section_table_truncated",
            ManySections => "many_sections",
            BadAlignment => "bad_alignment",
            LowAlignment => "low_alignment",
            SectionPastEndOfFile => "section_past_end_of_file",
            SectionsOverlap => "sections_overlap",
            SectionMisordered => "section_misordered",
            SizeOfImageMismatch => "size_of_image_mismatch",
            SizeOfHeadersMismatch => "size_of_headers_mismatch",
            EntryOutsideImage => "entry_outside_image",
            EntryNotExecutable => "entry_not_executable",
            Overlay => "overlay",
            DirectoryUnmapped => "directory_unmapped",
            ImportsTruncated => "imports_truncated",
            ImportNameBad => "import_name_bad",
            ExportsTruncated => "exports_truncated",
            ExportNameBad => "export_name_bad",
            RelocationsTruncated => "relocations_truncated",
            RelocationUnknownType => "relocation_unknown_type",
            ExceptionTableTruncated => "exception_table_truncated",
            ExceptionEntryBad => "exception_entry_bad",
            TlsTruncated => "tls_truncated",
            TlsCallbackOutside => "tls_callback_outside",
            DebugDirectoryTruncated => "debug_directory_truncated",
            CodeViewBad => "codeview_bad",
            SymbolTableTruncated => "symbol_table_truncated",
            OutputCapped => "output_capped",
        }
    }

    pub fn category(self) -> Category {
        use DiagnosticKind::*;
        match self {
            SizeOfImageMismatch
            | SizeOfHeadersMismatch
            | SectionMisordered
            | EntryNotExecutable
            | TlsCallbackOutside
            | Overlay => Category::Consistency,
            BadOptionalMagic | NotExecutableImage | BadAlignment | EntryOutsideImage
            | SectionsOverlap => Category::Loader,
            _ => Category::Format,
        }
    }
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub kind: DiagnosticKind,
    /// What was found, in English.
    pub message: String,
    /// File offset of the bytes involved, when there is one.
    pub offset: Option<u64>,
}

impl Diagnostic {
    pub fn category(&self) -> Category {
        self.kind.category()
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// At most this many diagnostics of one kind are kept; the rest are counted
/// in one [`DiagnosticKind::OutputCapped`] note per kind.
pub const MAX_DIAGNOSTICS_PER_KIND: usize = 16;

/// Collects diagnostics, capped per kind.
#[derive(Debug, Default)]
pub(crate) struct Sink {
    pub(crate) out: Vec<Diagnostic>,
    counts: std::collections::BTreeMap<DiagnosticKind, usize>,
    /// When false, nothing is recorded (plain accessors).
    pub(crate) on: bool,
}

impl Sink {
    pub(crate) fn recording() -> Sink {
        Sink {
            on: true,
            ..Sink::default()
        }
    }

    pub(crate) fn quiet() -> Sink {
        Sink::default()
    }

    pub(crate) fn push(
        &mut self,
        severity: Severity,
        kind: DiagnosticKind,
        offset: Option<u64>,
        message: impl FnOnce() -> String,
    ) {
        if !self.on {
            return;
        }
        let n = self.counts.entry(kind).or_insert(0);
        *n += 1;
        if *n <= MAX_DIAGNOSTICS_PER_KIND {
            self.out.push(Diagnostic {
                severity,
                kind,
                message: message(),
                offset,
            });
        }
    }

    pub(crate) fn finish(mut self) -> Vec<Diagnostic> {
        for (&kind, &n) in &self.counts {
            if n > MAX_DIAGNOSTICS_PER_KIND {
                self.out.push(Diagnostic {
                    severity: Severity::Info,
                    kind: DiagnosticKind::OutputCapped,
                    message: format!(
                        "{} more `{}` findings not listed",
                        n - MAX_DIAGNOSTICS_PER_KIND,
                        kind.name()
                    ),
                    offset: None,
                });
            }
        }
        self.out
    }
}

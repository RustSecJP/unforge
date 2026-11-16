use core::fmt;

/// Something that could not be read at all.
///
/// The reader is tolerant: anything that can be read is read, and anomalies
/// are reported as [`crate::Diagnostic`]s by [`crate::ElfFile::audit`]. An
/// `Error` is returned only where there is genuinely nothing to give back:
/// no ELF header, an index past its table, a name offset past its string
/// table. The reader never panics on malformed input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The first four bytes are not `\x7fELF`.
    BadMagic([u8; 4]),
    /// No layout (class, byte order) is supported by any clue: `EI_CLASS`
    /// and `EI_DATA` are invalid, `e_machine` is unknown in both byte orders
    /// and no header size field matches either class.
    UndeterminedLayout { ident_class: u8, ident_data: u8 },
    /// A structure that must be read whole does not fit inside the file.
    OutOfBounds {
        what: &'static str,
        offset: u64,
        size: u64,
        file_len: u64,
    },
    /// An `offset + size` computation overflowed.
    Overflow { what: &'static str },
    /// An index (section, string table, ...) points past the end of its table.
    BadIndex {
        what: &'static str,
        index: u64,
        len: u64,
    },
    /// A string table offset is past the end or the string is not NUL-terminated.
    BadString { offset: u64 },
    /// The section exists but has the wrong type for the requested operation.
    WrongSectionType { what: &'static str, sh_type: u32 },
    /// The file has no such part (e.g. no `PT_DYNAMIC`, or a symbol table
    /// without a usable string table).
    Missing { what: &'static str },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadMagic(m) => write!(f, "not an ELF file (magic {m:02x?})"),
            Error::UndeterminedLayout {
                ident_class,
                ident_data,
            } => write!(
                f,
                "cannot determine the layout: EI_CLASS {ident_class:#x} and EI_DATA {ident_data:#x} are invalid and no header field identifies a class or byte order"
            ),
            Error::OutOfBounds {
                what,
                offset,
                size,
                file_len,
            } => write!(
                f,
                "{what}: range {offset:#x}+{size:#x} is outside the file ({file_len:#x} bytes)"
            ),
            Error::Overflow { what } => write!(f, "{what}: arithmetic overflow"),
            Error::BadIndex { what, index, len } => {
                write!(f, "{what}: index {index} out of range (len {len})")
            }
            Error::BadString { offset } => {
                write!(
                    f,
                    "string at offset {offset:#x} is out of range or unterminated"
                )
            }
            Error::WrongSectionType { what, sh_type } => {
                write!(f, "{what}: unexpected section type {sh_type:#x}")
            }
            Error::Missing { what } => write!(f, "{what}: not present"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

//! Zero-copy table views.
//!
//! A table in an ELF file is `count` entries, `entsize` bytes apart, of one of
//! the on-disk structures in [`crate::raw`]. Nothing here copies a table:
//!
//! - [`Table<'data, R>`] borrows the input. When the stride equals
//!   `size_of::<R>()` it holds a `&'data [R]` obtained with
//!   `<[R]>::ref_from_bytes` (every raw structure is `Unaligned`, so this cannot
//!   fail because of alignment); otherwise it walks `stride`-sized chunks and
//!   borrows the first `size_of::<R>()` bytes of each with `R::ref_from_bytes`.
//! - [`LayoutTable<'data, K>`] hides which of the four (class, byte order)
//!   layouts the file uses behind one enum, and widens each entry into the
//!   class-independent type (`K::Wide`, e.g. [`crate::ProgramHeader`]) only
//!   when it is accessed.
//!
//! Neither type allocates. Their memory footprint is a few words regardless of
//! the table size.

use core::fmt;
use core::mem::size_of;

use zerocopy::byteorder::{BigEndian, LittleEndian};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::raw::{Dyn32, Dyn64, Phdr32, Phdr64, Shdr32, Shdr64, Sym32, Sym64};
use crate::{Class, DynamicEntry, Endian, ProgramHeader, SectionHeader, Symbol};

/// An on-disk structure that can be widened into a class-independent value.
pub trait RawEntry: FromBytes + KnownLayout + Immutable + Unaligned + Sized {
    /// The widened, class- and byte-order-independent type.
    type Wide: Copy;
    /// Decode this entry. Pure and infallible: every bit pattern is valid.
    fn widen(&self) -> Self::Wide;
}

// ---------------------------------------------------------------------------
// Table<'data, R>
// ---------------------------------------------------------------------------

/// `len` entries of type `R` borrowed from the input.
pub struct Table<'data, R> {
    repr: Repr<'data, R>,
}

enum Repr<'data, R> {
    /// The stride equals `size_of::<R>()`: a plain slice of raw structures.
    Packed(&'data [R]),
    /// The stride is larger: entry `i` is the `size_of::<R>()`-byte prefix of
    /// `bytes[i * stride..]`.
    Strided {
        bytes: &'data [u8],
        stride: usize,
        len: usize,
    },
}

impl<R> Clone for Repr<'_, R> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<R> Copy for Repr<'_, R> {}
impl<R> Clone for Table<'_, R> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<R> Copy for Table<'_, R> {}

impl<R> fmt::Debug for Table<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (len, stride) = match self.repr {
            Repr::Packed(s) => (s.len(), size_of::<R>()),
            Repr::Strided { stride, len, .. } => (len, stride),
        };
        f.debug_struct("Table")
            .field("len", &len)
            .field("stride", &stride)
            .finish()
    }
}

impl<'data, R: RawEntry> Table<'data, R> {
    /// The empty table.
    pub fn empty() -> Self {
        Table {
            repr: Repr::Packed(&[]),
        }
    }

    /// At most `max_len` entries, `stride` bytes apart, from the start of
    /// `bytes`. Entries that do not fit in `bytes` are not included: the
    /// length is the number of entries whose `size_of::<R>()` bytes are all
    /// inside `bytes`. Returns `None` if `stride < size_of::<R>()`.
    pub fn new(bytes: &'data [u8], stride: usize, max_len: u64) -> Option<Self> {
        let size = size_of::<R>();
        if stride < size || size == 0 {
            return None;
        }
        // Entries whose fixed-size prefix fits: the last one may lack the
        // padding up to `stride`, which is never read.
        let fit = match bytes.len().checked_sub(size) {
            None => 0,
            Some(rest) => rest / stride + 1,
        };
        let len = usize::try_from(max_len).map_or(fit, |m| m.min(fit));
        if stride == size {
            let n = len.checked_mul(size)?;
            let prefix = bytes.get(..n)?;
            if let Ok(slice) = <[R]>::ref_from_bytes(prefix) {
                return Some(Table {
                    repr: Repr::Packed(slice),
                });
            }
        }
        Some(Table {
            repr: Repr::Strided { bytes, stride, len },
        })
    }

    pub fn len(&self) -> usize {
        match self.repr {
            Repr::Packed(s) => s.len(),
            Repr::Strided { len, .. } => len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Distance between entries in bytes (`e_phentsize`, `sh_entsize`, ...).
    pub fn stride(&self) -> usize {
        match self.repr {
            Repr::Packed(_) => size_of::<R>(),
            Repr::Strided { stride, .. } => stride,
        }
    }

    /// The raw entries as a slice, when they are packed (stride ==
    /// `size_of::<R>()`). `None` for a strided table.
    pub fn as_slice(&self) -> Option<&'data [R]> {
        match self.repr {
            Repr::Packed(s) => Some(s),
            Repr::Strided { .. } => None,
        }
    }

    /// The raw entry `index`, borrowed from the input.
    pub fn get(&self, index: usize) -> Option<&'data R> {
        match self.repr {
            Repr::Packed(s) => s.get(index),
            Repr::Strided { bytes, stride, len } => {
                if index >= len {
                    return None;
                }
                let start = index.checked_mul(stride)?;
                let end = start.checked_add(size_of::<R>())?;
                R::ref_from_bytes(bytes.get(start..end)?).ok()
            }
        }
    }

    /// The first `n` entries (or all, if there are fewer).
    pub fn truncated(self, n: usize) -> Self {
        match self.repr {
            Repr::Packed(s) => Table {
                repr: Repr::Packed(s.get(..n).unwrap_or(s)),
            },
            Repr::Strided { bytes, stride, len } => Table {
                repr: Repr::Strided {
                    bytes,
                    stride,
                    len: len.min(n),
                },
            },
        }
    }

    pub fn iter(&self) -> TableIter<'data, R> {
        TableIter {
            table: *self,
            front: 0,
            back: self.len(),
        }
    }
}

/// Iterator over the raw entries of a [`Table`].
pub struct TableIter<'data, R> {
    table: Table<'data, R>,
    front: usize,
    back: usize,
}

impl<R> Clone for TableIter<'_, R> {
    fn clone(&self) -> Self {
        TableIter {
            table: self.table,
            front: self.front,
            back: self.back,
        }
    }
}

impl<R> fmt::Debug for TableIter<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TableIter")
            .field("front", &self.front)
            .field("back", &self.back)
            .finish()
    }
}

impl<'data, R: RawEntry> Iterator for TableIter<'data, R> {
    type Item = &'data R;
    fn next(&mut self) -> Option<&'data R> {
        while self.front < self.back {
            let i = self.front;
            self.front += 1;
            if let Some(r) = self.table.get(i) {
                return Some(r);
            }
        }
        None
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.back - self.front;
        (n, Some(n))
    }
}

impl<'data, R: RawEntry> DoubleEndedIterator for TableIter<'data, R> {
    fn next_back(&mut self) -> Option<&'data R> {
        while self.front < self.back {
            self.back -= 1;
            if let Some(r) = self.table.get(self.back) {
                return Some(r);
            }
        }
        None
    }
}

// `get(i)` succeeds for every `i < len` by construction, so the count is exact.
impl<R: RawEntry> ExactSizeIterator for TableIter<'_, R> {}

// ---------------------------------------------------------------------------
// Entry kinds and the layout-dispatched table.
// ---------------------------------------------------------------------------

mod sealed {
    pub trait Sealed {}
}

/// A family of on-disk structures: the same entry in the four layouts.
/// Implemented by [`PhdrKind`], [`ShdrKind`], [`SymKind`] and [`DynKind`] only.
pub trait EntryKind: sealed::Sealed {
    type Wide: Copy;
    type L32: RawEntry<Wide = Self::Wide>;
    type B32: RawEntry<Wide = Self::Wide>;
    type L64: RawEntry<Wide = Self::Wide>;
    type B64: RawEntry<Wide = Self::Wide>;
}

macro_rules! kind {
    ($(#[$m:meta])* $name:ident, $wide:ty, $t32:ident, $t64:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name;
        impl sealed::Sealed for $name {}
        impl EntryKind for $name {
            type Wide = $wide;
            type L32 = $t32<LittleEndian>;
            type B32 = $t32<BigEndian>;
            type L64 = $t64<LittleEndian>;
            type B64 = $t64<BigEndian>;
        }
    };
}

kind!(
    /// Program headers (`Elf32_Phdr` / `Elf64_Phdr`).
    PhdrKind,
    ProgramHeader,
    Phdr32,
    Phdr64
);
kind!(
    /// Section headers (`Elf32_Shdr` / `Elf64_Shdr`).
    ShdrKind,
    SectionHeader,
    Shdr32,
    Shdr64
);
kind!(
    /// Symbols (`Elf32_Sym` / `Elf64_Sym`), widened without `SHN_XINDEX`
    /// resolution (see [`crate::SymbolTable`] for the resolved view).
    SymKind,
    Symbol,
    Sym32,
    Sym64
);
kind!(
    /// Dynamic entries (`Elf32_Dyn` / `Elf64_Dyn`).
    DynKind,
    DynamicEntry,
    Dyn32,
    Dyn64
);

/// The raw table in whichever layout the file uses.
#[non_exhaustive]
pub enum AnyTable<'data, K: EntryKind> {
    Elf32Le(Table<'data, K::L32>),
    Elf32Be(Table<'data, K::B32>),
    Elf64Le(Table<'data, K::L64>),
    Elf64Be(Table<'data, K::B64>),
}

impl<K: EntryKind> Clone for AnyTable<'_, K> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<K: EntryKind> Copy for AnyTable<'_, K> {}

macro_rules! dispatch {
    ($any:expr, $t:ident => $e:expr) => {
        match $any {
            AnyTable::Elf32Le($t) => $e,
            AnyTable::Elf32Be($t) => $e,
            AnyTable::Elf64Le($t) => $e,
            AnyTable::Elf64Be($t) => $e,
        }
    };
}

/// A table of `K` entries in the file's layout, widened on access.
///
/// One type for all four (class, byte order) layouts; the choice is a single
/// enum match per access. `Copy`, allocation-free, borrows the input.
pub struct LayoutTable<'data, K: EntryKind> {
    any: AnyTable<'data, K>,
}

impl<K: EntryKind> Clone for LayoutTable<'_, K> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<K: EntryKind> Copy for LayoutTable<'_, K> {}

impl<K: EntryKind> fmt::Debug for LayoutTable<'_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (class, endian) = self.layout();
        f.debug_struct("LayoutTable")
            .field("class", &class)
            .field("endian", &endian)
            .field("len", &self.len())
            .field("stride", &self.stride())
            .finish()
    }
}

impl<'data, K: EntryKind> LayoutTable<'data, K> {
    /// See [`Table::new`]. `None` if `stride` is smaller than the structure
    /// of this layout.
    pub fn new(
        class: Class,
        endian: Endian,
        bytes: &'data [u8],
        stride: usize,
        max_len: u64,
    ) -> Option<Self> {
        let any = match (class, endian) {
            (Class::Elf32, Endian::Little) => {
                AnyTable::Elf32Le(Table::new(bytes, stride, max_len)?)
            }
            (Class::Elf32, Endian::Big) => AnyTable::Elf32Be(Table::new(bytes, stride, max_len)?),
            (Class::Elf64, Endian::Little) => {
                AnyTable::Elf64Le(Table::new(bytes, stride, max_len)?)
            }
            (Class::Elf64, Endian::Big) => AnyTable::Elf64Be(Table::new(bytes, stride, max_len)?),
        };
        Some(LayoutTable { any })
    }

    /// The empty table of this layout.
    pub fn empty(class: Class, endian: Endian) -> Self {
        let any = match (class, endian) {
            (Class::Elf32, Endian::Little) => AnyTable::Elf32Le(Table::empty()),
            (Class::Elf32, Endian::Big) => AnyTable::Elf32Be(Table::empty()),
            (Class::Elf64, Endian::Little) => AnyTable::Elf64Le(Table::empty()),
            (Class::Elf64, Endian::Big) => AnyTable::Elf64Be(Table::empty()),
        };
        LayoutTable { any }
    }

    /// `size_of` the raw structure in this layout.
    pub fn entry_size(class: Class) -> usize {
        match class {
            Class::Elf32 => size_of::<K::L32>(),
            Class::Elf64 => size_of::<K::L64>(),
        }
    }

    pub fn layout(&self) -> (Class, Endian) {
        match self.any {
            AnyTable::Elf32Le(_) => (Class::Elf32, Endian::Little),
            AnyTable::Elf32Be(_) => (Class::Elf32, Endian::Big),
            AnyTable::Elf64Le(_) => (Class::Elf64, Endian::Little),
            AnyTable::Elf64Be(_) => (Class::Elf64, Endian::Big),
        }
    }

    pub fn len(&self) -> usize {
        dispatch!(self.any, t => t.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn stride(&self) -> usize {
        dispatch!(self.any, t => t.stride())
    }

    /// Entry `index`, widened. `None` past the end.
    pub fn get(&self, index: usize) -> Option<K::Wide> {
        dispatch!(self.any, t => t.get(index).map(RawEntry::widen))
    }

    /// The raw table, for callers that want the on-disk structures.
    pub fn raw(&self) -> AnyTable<'data, K> {
        self.any
    }

    /// The first `n` entries.
    pub fn truncated(self, n: usize) -> Self {
        let any = match self.any {
            AnyTable::Elf32Le(t) => AnyTable::Elf32Le(t.truncated(n)),
            AnyTable::Elf32Be(t) => AnyTable::Elf32Be(t.truncated(n)),
            AnyTable::Elf64Le(t) => AnyTable::Elf64Le(t.truncated(n)),
            AnyTable::Elf64Be(t) => AnyTable::Elf64Be(t.truncated(n)),
        };
        LayoutTable { any }
    }

    pub fn iter(&self) -> LayoutIter<'data, K> {
        let inner = match self.any {
            AnyTable::Elf32Le(t) => IterRepr::Elf32Le(t.iter()),
            AnyTable::Elf32Be(t) => IterRepr::Elf32Be(t.iter()),
            AnyTable::Elf64Le(t) => IterRepr::Elf64Le(t.iter()),
            AnyTable::Elf64Be(t) => IterRepr::Elf64Be(t.iter()),
        };
        LayoutIter { inner }
    }
}

impl<'data, K: EntryKind> IntoIterator for LayoutTable<'data, K> {
    type Item = K::Wide;
    type IntoIter = LayoutIter<'data, K>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'data, K: EntryKind> IntoIterator for &LayoutTable<'data, K> {
    type Item = K::Wide;
    type IntoIter = LayoutIter<'data, K>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

enum IterRepr<'data, K: EntryKind> {
    Elf32Le(TableIter<'data, K::L32>),
    Elf32Be(TableIter<'data, K::B32>),
    Elf64Le(TableIter<'data, K::L64>),
    Elf64Be(TableIter<'data, K::B64>),
}

/// Iterator over a [`LayoutTable`], yielding widened entries.
pub struct LayoutIter<'data, K: EntryKind> {
    inner: IterRepr<'data, K>,
}

impl<K: EntryKind> Clone for LayoutIter<'_, K> {
    fn clone(&self) -> Self {
        let inner = match &self.inner {
            IterRepr::Elf32Le(i) => IterRepr::Elf32Le(i.clone()),
            IterRepr::Elf32Be(i) => IterRepr::Elf32Be(i.clone()),
            IterRepr::Elf64Le(i) => IterRepr::Elf64Le(i.clone()),
            IterRepr::Elf64Be(i) => IterRepr::Elf64Be(i.clone()),
        };
        LayoutIter { inner }
    }
}

impl<K: EntryKind> fmt::Debug for LayoutIter<'_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LayoutIter")
            .field("remaining", &self.len())
            .finish()
    }
}

macro_rules! iter_dispatch {
    ($s:expr, $i:ident => $e:expr) => {
        match $s {
            IterRepr::Elf32Le($i) => $e,
            IterRepr::Elf32Be($i) => $e,
            IterRepr::Elf64Le($i) => $e,
            IterRepr::Elf64Be($i) => $e,
        }
    };
}

impl<K: EntryKind> Iterator for LayoutIter<'_, K> {
    type Item = K::Wide;
    fn next(&mut self) -> Option<K::Wide> {
        iter_dispatch!(&mut self.inner, i => i.next().map(RawEntry::widen))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        iter_dispatch!(&self.inner, i => i.size_hint())
    }
}

impl<K: EntryKind> DoubleEndedIterator for LayoutIter<'_, K> {
    fn next_back(&mut self) -> Option<K::Wide> {
        iter_dispatch!(&mut self.inner, i => i.next_back().map(RawEntry::widen))
    }
}

impl<K: EntryKind> ExactSizeIterator for LayoutIter<'_, K> {}

/// The program header table of a file.
pub type ProgramHeaders<'data> = LayoutTable<'data, PhdrKind>;
/// The section header table of a file.
pub type SectionHeaders<'data> = LayoutTable<'data, ShdrKind>;

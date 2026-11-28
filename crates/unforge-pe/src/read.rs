//! Little-endian reads that never panic.

pub(crate) fn u8_at(b: &[u8], at: usize) -> Option<u8> {
    b.get(at).copied()
}

pub(crate) fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([*s.first()?, *s.get(1)?]))
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Some(u32::from_le_bytes(a))
}

pub(crate) fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    let s = b.get(at..at.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// A 4- or 8-byte little-endian word.
pub(crate) fn word_at(b: &[u8], at: usize, size: usize) -> Option<u64> {
    if size == 8 {
        u64_at(b, at)
    } else {
        u32_at(b, at).map(u64::from)
    }
}

/// The NUL-terminated string at the start of `b`, at most `max` bytes.
/// Returns the bytes before the NUL and whether the string was cut (no NUL
/// within `max` bytes or before the end of `b`).
pub(crate) fn cstr(b: &[u8], max: usize) -> (&[u8], bool) {
    let window = b.get(..b.len().min(max)).unwrap_or_default();
    match window.iter().position(|&c| c == 0) {
        Some(n) => (window.get(..n).unwrap_or_default(), false),
        None => (window, true),
    }
}

pub(crate) fn align_up(v: u64, a: u64) -> u64 {
    if a <= 1 {
        return v;
    }
    match v.checked_add(a - 1) {
        Some(x) => x / a * a,
        None => u64::MAX / a * a,
    }
}

pub(crate) fn usize_of(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads() {
        let b = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(u16_at(&b, 0), Some(0x0201));
        assert_eq!(u32_at(&b, 5), Some(0x0908_0706));
        assert_eq!(u32_at(&b, 6), None);
        assert_eq!(u64_at(&b, usize::MAX), None);
        assert_eq!(word_at(&b, 0, 4), Some(0x0403_0201));
        assert_eq!(cstr(b"ab\0c", 10), (&b"ab"[..], false));
        assert_eq!(cstr(b"abc", 2), (&b"ab"[..], true));
        assert_eq!(align_up(0x201, 0x200), 0x400);
        assert_eq!(align_up(5, 0), 5);
        assert_eq!(align_up(u64::MAX, 0x1000), u64::MAX / 0x1000 * 0x1000);
    }
}

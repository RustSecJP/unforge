//! FNV-1a, 64-bit (Fowler, Noll, Vo; <http://www.isthe.com/chongo/tech/comp/fnv/>,
//! also IETF draft-eastlake-fnv).
//!
//! The fingerprint hash must never change between platforms, Rust versions
//! or releases of this crate, because databases built today are matched
//! against binaries later. FNV-1a is defined byte by byte (no word size,
//! no endianness, no seed), takes ten lines, and needs no dependency.
//! `std`'s `DefaultHasher` is explicitly not stable across releases, so it
//! is not used.
//!
//! FNV-1a is not collision resistant against an adversary. That is fine
//! here: a binary that wants to hide its code can do far more than craft a
//! collision, and among `n` honest functions the chance of any two random
//! 64-bit values colliding is about `n² / 2⁶⁵` (3·10⁻⁸ for a million).

/// FNV-1a 64 offset basis.
pub const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64 prime.
pub const PRIME: u64 = 0x0000_0100_0000_01b3;

/// An FNV-1a 64 state.
#[derive(Debug, Clone, Copy)]
pub struct Fnv64(u64);

impl Default for Fnv64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Fnv64 {
    pub fn new() -> Self {
        Fnv64(OFFSET_BASIS)
    }

    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(PRIME);
        }
    }

    pub fn finish(&self) -> u64 {
        self.0
    }
}

/// FNV-1a 64 of `bytes`.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = Fnv64::new();
    h.write(bytes);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors from the FNV reference test suite.
    #[test]
    fn reference_vectors() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }
}

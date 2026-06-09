//! Little-endian wire primitives shared by all protocol code.

pub struct Rdr<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rdr<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(s)
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_le_bytes(s.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    }
}

pub trait Put {
    fn p8(&mut self, v: u8);
    fn p16(&mut self, v: u16);
    fn p32(&mut self, v: u32);
    fn p64(&mut self, v: u64);
    fn pbytes(&mut self, v: &[u8]);
    fn zeros(&mut self, n: usize);
    fn patch32(&mut self, off: usize, v: u32);
    /// Pad with zeros so that (len - base) is a multiple of 8.
    fn pad8(&mut self, base: usize);
}

impl Put for Vec<u8> {
    fn p8(&mut self, v: u8) {
        self.push(v);
    }
    fn p16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn p32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn p64(&mut self, v: u64) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn pbytes(&mut self, v: &[u8]) {
        self.extend_from_slice(v);
    }
    fn zeros(&mut self, n: usize) {
        self.resize(self.len() + n, 0);
    }
    fn patch32(&mut self, off: usize, v: u32) {
        self[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn pad8(&mut self, base: usize) {
        let rem = (self.len() - base) % 8;
        if rem != 0 {
            self.zeros(8 - rem);
        }
    }
}

pub fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

pub fn from_utf16le(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdr_put_roundtrip() {
        let mut v: Vec<u8> = Vec::new();
        v.p8(0xAB);
        v.p16(0x1234);
        v.p32(0xDEADBEEF);
        v.p64(0x0102030405060708);
        let mut r = Rdr::new(&v);
        assert_eq!(r.u8(), Some(0xAB));
        assert_eq!(r.u16(), Some(0x1234));
        assert_eq!(r.u32(), Some(0xDEADBEEF));
        assert_eq!(r.u64(), Some(0x0102030405060708));
        assert_eq!(r.u8(), None);
    }

    #[test]
    fn utf16_roundtrip() {
        let s = "héllo\\wörld";
        assert_eq!(from_utf16le(&utf16le(s)), s);
    }

    #[test]
    fn pad8_works() {
        let mut v: Vec<u8> = vec![0; 4];
        v.pbytes(b"abc");
        v.pad8(4);
        assert_eq!((v.len() - 4) % 8, 0);
    }
}

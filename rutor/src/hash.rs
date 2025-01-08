#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha1(pub(crate) [u8; 20]);

impl Sha1 {
    pub fn hash(buf: &[u8]) -> Sha1 {
        use sha1::Digest;
        let mut hasher = sha1::Sha1::default();
        hasher.update(buf);
        Sha1(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Sha1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sha1(")?;
        for v in self.0 {
            write!(f, "{:x}", v)?;
        }
        f.write_str(")")?;
        Ok(())
    }
}

impl std::fmt::Display for Sha1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for v in self.0 {
            write!(f, "{:x}", v)?;
        }
        Ok(())
    }
}

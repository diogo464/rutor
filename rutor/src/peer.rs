#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 20]);

impl PeerId {
    pub fn new(id: [u8; 20]) -> Self {
        Self(id)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for PeerId {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerId(")?;
        for v in self.0 {
            write!(f, "{:x}", v)?;
        }
        f.write_str(")")?;
        Ok(())
    }
}

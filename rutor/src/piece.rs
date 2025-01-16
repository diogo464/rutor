#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PieceIdx(pub(crate) u32);

impl std::fmt::Display for PieceIdx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Piece({})", self.0)
    }
}

impl From<PieceIdx> for u32 {
    fn from(value: PieceIdx) -> Self {
        value.0
    }
}

impl From<u32> for PieceIdx {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl PieceIdx {
    pub fn new(index: u32) -> Self {
        Self(index)
    }
}

#[derive(Default, Clone)]
pub struct PieceBitfield {
    data: Vec<u8>,
    size: u32,
}

impl PieceBitfield {
    pub fn new() -> Self {
        Default::default()
    }

    // size is the number of bits required
    pub fn with_size(size: u32) -> Self {
        let data = vec![0u8; Self::required_vec_capacity(size)];
        Self { data, size }
    }

    pub fn from_vec(bytes: Vec<u8>, size: u32) -> Self {
        let mut data = bytes;
        data.resize(size.try_into().unwrap(), 0);
        Self { data, size }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    pub fn has_piece(&self, index: PieceIdx) -> bool {
        let (byte_index, bit_index) = self.get_indices(index.0);
        (self.data[byte_index] & (1 << bit_index)) > 0
    }

    pub fn set_piece(&mut self, index: PieceIdx) {
        let (byte_index, bit_index) = self.get_indices(index.0);
        self.data[byte_index] = self.data[byte_index] | (1 << bit_index);
    }

    pub fn unset_piece(&mut self, index: PieceIdx) {
        let (byte_index, bit_index) = self.get_indices(index.0);
        self.data[byte_index] = self.data[byte_index] & !(1 << bit_index);
    }

    pub fn piece_capacity(&self) -> u32 {
        (self.data.len() * 8) as u32
    }

    pub fn resize(&mut self, new_size: u32) {
        self.data.resize(Self::required_vec_capacity(new_size), 0);
        self.size = new_size;
    }

    pub fn num_set(&self) -> u32 {
        self.pieces().count() as u32
    }

    pub fn num_unset(&self) -> u32 {
        self.missing_pieces().count() as u32
    }

    pub fn fill(&mut self) {
        for i in 0..self.size {
            self.set_piece(PieceIdx::from(i));
        }
    }

    pub fn clear(&mut self) {
        self.data.iter_mut().for_each(|v| *v = 0);
    }

    pub fn complete(&self) -> bool {
        for i in 0..self.size {
            if !self.has_piece(PieceIdx::from(i)) {
                return false;
            }
        }
        true
    }

    pub fn len(&self) -> u32 {
        self.size
    }

    pub fn bytes(&self) -> &[u8] {
        self.as_ref()
    }

    /// Iterator over pieces that this bitfield contains
    pub fn pieces(&self) -> impl Iterator<Item = PieceIdx> + '_ {
        (0..self.len())
            .filter(move |p| self.has_piece(PieceIdx::new(*p)))
            .map(|p| PieceIdx::new(p))
    }

    pub fn missing_pieces(&self) -> impl Iterator<Item = PieceIdx> + '_ {
        (0..self.len())
            .filter(move |p| !self.has_piece(PieceIdx::new(*p)))
            .map(|p| PieceIdx::new(p))
    }

    pub fn missing_pieces_in<'s>(&'s self, other: &'s Self) -> impl Iterator<Item = PieceIdx> + 's {
        assert_eq!(self.len(), other.len());
        (0..self.len())
            .filter(move |p| {
                let index = PieceIdx::from(*p);
                !self.has_piece(index) && other.has_piece(index)
            })
            .map(|p| PieceIdx::new(p))
    }

    pub fn contains_missing_in(&self, other: &Self) -> bool {
        other.missing_pieces_in(self).next().is_some()
    }

    // returns (byte_index, bit_index), panics if index is invalid
    fn get_indices(&self, index: u32) -> (usize, usize) {
        if index > self.piece_capacity() {
            panic!("Bitfield not large enough for index : {}", index);
        }
        let byte_index = index as usize / 8;
        let bit_index = 7 - index as usize % 8;
        (byte_index, bit_index)
    }

    fn required_vec_capacity(num_bits: u32) -> usize {
        (num_bits / 8 + (num_bits % 8).min(1)) as usize
    }
}

impl std::fmt::Debug for PieceBitfield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PieceBitfield")
            .field("bits", &self.size)
            .finish()
    }
}

impl AsRef<[u8]> for PieceBitfield {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn creation() {
        let bf = PieceBitfield::with_size(33);
        assert_eq!(bf.piece_capacity(), 40);
    }

    #[test]
    fn creation_all_zeros() {
        let bf = PieceBitfield::with_size(32);
        for i in 0..bf.piece_capacity() {
            assert!(!bf.has_piece(PieceIdx::new(i)));
        }
    }

    #[test]
    fn setting_bits() {
        let mut bf = PieceBitfield::with_size(32);
        bf.set_piece(PieceIdx::new(5));
        bf.set_piece(PieceIdx::new(9));
        bf.set_piece(PieceIdx::new(30));

        assert!(bf.has_piece(PieceIdx::new(5)));
        assert!(bf.has_piece(PieceIdx::new(9)));
        assert!(bf.has_piece(PieceIdx::new(30)));

        for i in 0..bf.piece_capacity() {
            assert!(!bf.has_piece(PieceIdx::new(i)) || i == 5 || i == 9 || i == 30);
        }
    }

    #[test]
    fn removing_bits() {
        let mut bf = PieceBitfield::with_size(32);
        bf.set_piece(PieceIdx::new(5));
        bf.set_piece(PieceIdx::new(9));
        bf.set_piece(PieceIdx::new(30));

        bf.unset_piece(PieceIdx::new(9));

        assert!(bf.has_piece(PieceIdx::new(5)));
        assert!(bf.has_piece(PieceIdx::new(30)));

        for i in 0..bf.piece_capacity() {
            assert!(!bf.has_piece(PieceIdx::new(i)) || i == 5 || i == 30);
        }
    }

    #[test]
    fn missing_pieces_in() {
        let mut bf0 = PieceBitfield::with_size(32);
        let mut bf1 = PieceBitfield::with_size(32);

        bf0.set_piece(PieceIdx::new(5));
        bf0.set_piece(PieceIdx::new(9));
        bf0.set_piece(PieceIdx::new(30));

        bf1.set_piece(PieceIdx::new(9));

        let mut iter = bf1.missing_pieces_in(&bf0);
        assert_eq!(iter.next(), Some(PieceIdx::new(5)));
        assert_eq!(iter.next(), Some(PieceIdx::new(30)));
        assert_eq!(iter.next(), None);
    }
}

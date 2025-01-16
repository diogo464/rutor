use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{PieceIdx, Sha1};

struct TorrentInfoInner {
    announce: String,
    trackers: Vec<String>,
    name: String,
    comment: Option<String>,
    creator: Option<String>,
    piece_length: u32,
    pieces: Vec<Sha1>,
    info_hash: Sha1,
    files: Vec<TorrentFile>,
}

impl std::fmt::Debug for TorrentInfoInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Torrent \n\tAnnounce : {:?}\n\tName : {:?}\n\tComment : {:?}\n\tCreator : {:?}\n\tPiece length : {:?}\n\tFiles : {:#?}\n",
            self.announce, self.name, self.comment, self.creator, self.piece_length, self.files
        )
    }
}

#[derive(Clone)]
pub struct TorrentInfo(Arc<TorrentInfoInner>);

impl std::fmt::Debug for TorrentInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TorrentInfo {
    pub fn decode(buf: &[u8]) -> std::io::Result<Self> {
        let metainfo = bencode::decode::<Metainfo>(buf).map_err(std::io::Error::other)?;
        let mut files = Vec::with_capacity(metainfo.info.files.len());
        let mut offset = 0;
        for (index, file) in metainfo.info.files.into_iter().enumerate() {
            files.push(TorrentFile {
                index,
                start: offset,
                length: file.length,
                path: PathBuf::from(file.path),
            });
            offset += file.length;
        }

        Ok(Self(Arc::new(TorrentInfoInner {
            announce: metainfo.announce,
            trackers: metainfo.announce_list.into_iter().flatten().collect(),
            name: metainfo.info.name,
            comment: metainfo.comment,
            creator: metainfo.creator,
            piece_length: metainfo.info.piece_length,
            pieces: metainfo.info.pieces,
            info_hash: metainfo.info_hash,
            files,
        })))
    }

    pub fn announce(&self) -> &String {
        &self.0.announce
    }

    pub fn trackers(&self) -> &[String] {
        &self.0.trackers
    }

    pub fn name(&self) -> &str {
        self.0.name.as_str()
    }

    pub fn total_size(&self) -> u64 {
        self.0.files.iter().map(|f| f.length).sum()
    }

    pub fn info_hash(&self) -> Sha1 {
        self.0.info_hash
    }

    pub fn piece_length(&self) -> u32 {
        self.0.piece_length
    }

    pub fn piece_indices(&self) -> impl Iterator<Item = PieceIdx> {
        let piece_count = self.pieces_count();
        (0..piece_count).map(|i| PieceIdx::new(i))
    }

    pub fn piece_length_from_index(&self, piece_index: PieceIdx) -> u32 {
        let size = self.total_size();
        let q = size / self.piece_length() as u64;
        let r = size % self.piece_length() as u64;
        match (piece_index.0 as u64).cmp(&q) {
            std::cmp::Ordering::Greater => 0,
            std::cmp::Ordering::Equal => r as u32,
            std::cmp::Ordering::Less => self.piece_length(),
        }
    }

    pub fn piece_index_valid(&self, piece_index: PieceIdx) -> bool {
        piece_index.0 < self.pieces_count()
    }

    pub fn piece_request_valid(&self, piece_index: PieceIdx, begin: u32, length: u32) -> bool {
        if !self.piece_index_valid(piece_index) {
            return false;
        }

        let piece_length = self.piece_length_from_index(piece_index);
        begin.saturating_add(length) <= piece_length
    }

    pub fn piece_hash(&self, piece_index: PieceIdx) -> Option<Sha1> {
        self.0.pieces.get(piece_index.0 as usize).copied()
    }

    // returns the piece that contains that byte offset
    pub fn piece_at_offset(&self, location: u64) -> Option<PieceIdx> {
        if location >= self.total_size() {
            None
        } else {
            let index = location / self.piece_length() as u64;
            Some(PieceIdx::new(index as u32))
        }
    }

    pub fn files_from_piece<'a>(
        &'a self,
        piece_index: PieceIdx,
    ) -> impl Iterator<Item = TorrentFileRange<'a>> {
        let piece_start = piece_index.0 as u64 * self.piece_length() as u64;
        let piece_length = self.piece_length_from_index(piece_index);
        let current_file = match self
            .0
            .files
            .binary_search_by_key(&piece_start, |tf| tf.start)
        {
            Ok(cf) => cf,
            Err(cf) => cf - 1,
        };

        //println!("piece_start(in torrent) : {}", piece_start);
        //println!("piece_length : {}", piece_length);
        //println!("current_file(index) : {}", current_file);

        TorrentFileRangeIterator {
            info: self,
            piece_start,
            piece_length,
            current_file,
        }
    }

    pub fn pieces_count(&self) -> u32 {
        self.0.pieces.len() as u32
    }

    pub fn pieces(&self) -> &[Sha1] {
        &self.0.pieces
    }

    pub fn files(&self) -> &[TorrentFile] {
        &self.0.files
    }
}

#[derive(Debug, Clone)]
pub struct TorrentFile {
    index: usize,
    start: u64,
    length: u64,
    path: PathBuf,
    // TODO: add md5
}

impl TorrentFile {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Clone)]
pub struct TorrentFileRange<'a> {
    /// The file a given piece belongs to
    pub file: &'a TorrentFile,
    /// Where in the file should this piece be placed
    pub file_start: u64,
    /// Where in the piece does this file start
    pub piece_start: u32,
    /// How much of the piece bellongs to this file
    pub chunk_length: u32,
}

impl<'a> TorrentFileRange<'a> {
    pub fn piece_range(&self) -> std::ops::Range<usize> {
        self.piece_start as usize..(self.piece_start + self.chunk_length) as usize
    }
}

struct TorrentFileRangeIterator<'a> {
    info: &'a TorrentInfo,
    // Offset in the torrent where this piece starts
    piece_start: u64,
    piece_length: u32,
    // Index of the current file
    current_file: usize,
}

impl<'a> Iterator for TorrentFileRangeIterator<'a> {
    type Item = TorrentFileRange<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let curr_file = self.info.0.files.get(self.current_file)?;
        if curr_file.start > self.piece_start + self.piece_length as u64 {
            return None;
        }
        let file_start = self.piece_start.saturating_sub(curr_file.start);
        let file_end = curr_file.start + curr_file.length;
        let piece_start = curr_file.start.saturating_sub(self.piece_start) as u32;
        let chunk_length = file_end
            .saturating_sub(self.piece_start)
            .min(self.piece_length.saturating_sub(piece_start) as u64)
            as u32;
        self.current_file += 1;

        //println!("curr_file.start : {}", curr_file.start);
        //println!("File start : {}", file_start);
        //println!("piece_start(in torrent) : {}", self.piece_start);
        //println!("piece_start(in file) : {}", piece_start);
        //println!("chunk length : {}", chunk_length);

        Some(TorrentFileRange {
            file: curr_file,
            file_start,
            piece_start,
            chunk_length,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Metainfo {
    pub announce: String,
    pub announce_list: Vec<Vec<String>>,
    pub info: Info,
    pub info_hash: Sha1,
    pub creator: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InfoFile {
    pub path: String,
    pub length: u64,
}

#[derive(Debug, Clone)]
pub struct Info {
    pub name: String,
    pub piece_length: u32,
    pub length: u64,
    pub pieces: Vec<Sha1>,
    pub files: Vec<InfoFile>,
}

impl Info {
    pub fn piece_length(&self, index: u32) -> u32 {
        let mut l = self.length;
        l = l.saturating_sub(u64::from(index) * u64::from(self.piece_length));
        l.min(u64::from(self.piece_length)) as u32
    }
}

impl bencode::FromValue for InfoFile {
    fn from_value(value: &bencode::Value) -> bencode::Result<Self> {
        let dict = value.as_dict()?;
        let path = dict.require::<Vec<String>>(b"path")?.join("/");
        Ok(Self {
            length: dict.require(b"length")?,
            path,
        })
    }
}

impl bencode::FromValue for Info {
    fn from_value(value: &bencode::Value) -> bencode::Result<Self> {
        let dict = value.as_dict()?;
        let name = dict.require::<String>(b"name")?;
        let piece_length = dict.require(b"piece length")?;
        let pieces_bytes = dict.require_value(b"pieces")?.as_bytes()?;
        if pieces_bytes.len() % 20 != 0 {
            return Err(bencode::Error::message(
                "size of pieces byte string is not a multiple of 20",
            ));
        }

        let mut pieces = Vec::with_capacity(pieces_bytes.len() / 20);
        for i in 0..pieces_bytes.len() / 20 {
            let hash = &pieces_bytes[i * 20..(i + 1) * 20];
            pieces.push(Sha1(TryFrom::try_from(hash).unwrap()));
        }

        let mut files = Vec::new();
        let mut length = 0;
        let length_value = dict.find_value(b"length");
        let files_value = dict.find_value(b"files");
        match (length_value, files_value) {
            (Some(l), None) => match l.data {
                bencode::ValueData::Integer(l) => {
                    length = l as u64;
                    files.push(InfoFile {
                        path: name.clone(),
                        length,
                    })
                }
                _ => return Err(bencode::Error::message("length field must be an integer")),
            },
            (None, Some(f)) => match &f.data {
                bencode::ValueData::List(f) => {
                    for v in f {
                        let file = InfoFile::from_value(v)?;
                        length += file.length;
                        files.push(file);
                    }
                }
                _ => return Err(bencode::Error::message("files field must be a list")),
            },
            (Some(_), Some(_)) => {
                return Err(bencode::Error::message(
                    "info dictionary cannot contain both files and length field",
                ))
            }
            (None, None) => {
                return Err(bencode::Error::message(
                    "info dictionary must contain either files or length field",
                ))
            }
        }

        Ok(Self {
            name,
            piece_length,
            length,
            pieces,
            files,
        })
    }
}

impl bencode::FromValue for Metainfo {
    fn from_value(value: &bencode::Value) -> bencode::Result<Self> {
        let dict = value.as_dict()?;
        let announce = dict.require(b"announce")?;
        let announce_list = dict.find(b"announce-list")?.unwrap_or_default();
        let info_dict = dict.require_value(b"info")?;
        let info = Info::from_value(&info_dict)?;
        let info_hash = Sha1::hash(info_dict.bytes);
        let creator = dict.find(b"created by")?;
        let comment = dict.find(b"comment")?;
        Ok(Self {
            announce,
            announce_list,
            info,
            info_hash,
            creator,
            comment,
        })
    }
}

#[cfg(test)]
mod test_torrent_info {
    use super::*;

    const BUNNY_DATA: &'static [u8] = include_bytes!("../../bunny.torrent");

    #[test]
    fn bunny_decode() {
        let info = TorrentInfo::decode(&BUNNY_DATA).unwrap();
        insta::assert_yaml_snapshot!(info.name(), @"Big Buck Bunny");
        insta::assert_yaml_snapshot!(info.announce(), @r#""udp://tracker.leechers-paradise.org:6969""#);
        insta::assert_yaml_snapshot!(info.info_hash().to_string(), @"dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c");
        insta::assert_yaml_snapshot!(info.piece_length(), @"262144");
        insta::assert_yaml_snapshot!(info.pieces_count(), @"1055");
        insta::assert_yaml_snapshot!(info.total_size(), @"276445467");
        insta::assert_yaml_snapshot!(info.files().len(), @"3");

        let file_0 = &info.files()[0];
        insta::assert_yaml_snapshot!(file_0.path(), @"Big Buck Bunny.en.srt");
        insta::assert_yaml_snapshot!(file_0.index, @"0");
        insta::assert_yaml_snapshot!(file_0.start, @"0");
        insta::assert_yaml_snapshot!(file_0.length, @"140");

        let file_1 = &info.files()[1];
        insta::assert_yaml_snapshot!(file_1.path(), @"Big Buck Bunny.mp4");
        insta::assert_yaml_snapshot!(file_1.index, @"1");
        insta::assert_yaml_snapshot!(file_1.start, @"140");
        insta::assert_yaml_snapshot!(file_1.length, @"276134947");

        let file_2 = &info.files()[2];
        insta::assert_yaml_snapshot!(file_2.path(), @"poster.jpg");
        insta::assert_yaml_snapshot!(file_2.index, @"2");
        insta::assert_yaml_snapshot!(file_2.start, @"276135087");
        insta::assert_yaml_snapshot!(file_2.length, @"310380");
    }

    #[test]
    fn bunny_piece_0_range() {
        let info = TorrentInfo::decode(&BUNNY_DATA).unwrap();
        let ranges = info.files_from_piece(PieceIdx::new(0)).collect::<Vec<_>>();
        let piece_len = info.piece_length();
        let file_srt = &info.files()[0];
        let file_mp4 = &info.files()[1];
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].file.path(), file_srt.path());
        assert_eq!(ranges[1].file.path(), file_mp4.path());

        assert_eq!(ranges[0].file_start, 0);
        assert_eq!(ranges[1].file_start, 0);

        assert_eq!(ranges[0].piece_start, 0);
        assert_eq!(ranges[1].piece_start, file_srt.length as u32);

        assert_eq!(ranges[0].chunk_length, file_srt.length as u32);
        assert_eq!(ranges[1].chunk_length, piece_len - file_srt.length as u32);
    }
}

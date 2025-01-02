use std::{
    collections::VecDeque,
    io::{BufReader, BufWriter, Cursor, Read, Seek, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use clap::Parser;
use serde::Serialize;
use slotmap::{Key as _, SecondaryMap, SlotMap};

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha1([u8; 20]);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PieceIdx(u32);

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

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 20]);

impl PeerId {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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

type TrackerUrl = String;

struct TorrentInfoInner {
    announce: TrackerUrl,
    trackers: Vec<TrackerUrl>,
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

    pub fn announce(&self) -> &TrackerUrl {
        &self.0.announce
    }

    pub fn trackers(&self) -> &[TrackerUrl] {
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
        begin.saturating_add(length) > piece_length
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

    pub fn start(&self) -> &u64 {
        &self.start
    }

    pub fn length(&self) -> &u64 {
        &self.length
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

#[cfg(test)]
mod test_torrent_info {
    use super::*;

    const BUNNY_DATA: &'static [u8] = include_bytes!("../bunny.torrent");

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

type ArcMetaInfo = Arc<Metainfo>;

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

#[derive(Debug, Serialize)]
struct TrackerRequest<'a> {
    #[serde(skip)]
    info_hash: &'a [u8],
    #[serde(skip)]
    peer_id: &'a [u8],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
}

const PROTOCOL_ID: u64 = 0x41727101980;

trait Wire: Sized {
    fn encode<W: Write>(&self, writer: W) -> std::io::Result<()>;
    fn decode<R: Read>(reader: R) -> std::io::Result<Self>;
}

impl Wire for u16 {
    fn encode<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.to_be_bytes())
    }
    fn decode<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }
}

impl Wire for u32 {
    fn encode<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.to_be_bytes())
    }
    fn decode<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }
}

impl Wire for u64 {
    fn encode<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.to_be_bytes())
    }
    fn decode<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }
}

impl Wire for Ipv4Addr {
    fn encode<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.octets())
    }

    fn decode<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut octets = [0u8; 4];
        reader.read_exact(&mut octets)?;
        Ok(Ipv4Addr::from(octets))
    }
}

impl Wire for SocketAddrV4 {
    fn encode<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.ip().encode(&mut writer)?;
        self.port().encode(&mut writer)?;
        Ok(())
    }

    fn decode<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let ip = Ipv4Addr::decode(&mut reader)?;
        let port = u16::decode(&mut reader)?;
        Ok(SocketAddrV4::new(ip, port))
    }
}

impl Wire for Sha1 {
    fn encode<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self.as_bytes())
    }

    fn decode<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut sha1 = Sha1::default();
        reader.read_exact(&mut sha1.0)?;
        Ok(sha1)
    }
}

impl Wire for PeerId {
    fn encode<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self.as_bytes())
    }

    fn decode<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut peer_id = PeerId::default();
        reader.read_exact(&mut peer_id.0)?;
        Ok(peer_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Connect = 0,
    Announce = 1,
    Scrape = 2,
}

impl Wire for Action {
    fn encode<W: Write>(&self, writer: W) -> std::io::Result<()> {
        (*self as u32).encode(writer)
    }

    fn decode<R: Read>(reader: R) -> std::io::Result<Self> {
        let v = u32::decode(reader)?;
        match v {
            _ if v == Action::Connect as u32 => Ok(Action::Connect),
            _ if v == Action::Announce as u32 => Ok(Action::Announce),
            _ if v == Action::Scrape as u32 => Ok(Action::Scrape),
            _ => Err(invalid_data("invalid action value")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub transaction_id: u32,
}

impl Wire for ConnectRequest {
    fn encode<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        PROTOCOL_ID.encode(&mut writer)?;
        Action::Connect.encode(&mut writer)?;
        self.transaction_id.encode(&mut writer)?;
        Ok(())
    }

    fn decode<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let protocol_id = u64::decode(&mut reader)?;
        if protocol_id != PROTOCOL_ID {
            return Err(invalid_data("invalid protocol magic value"));
        }
        let action = Action::decode(&mut reader)?;
        if action != Action::Connect {
            return Err(invalid_data("expected action to be 'connect'"));
        }
        let transaction_id = u32::decode(&mut reader)?;
        Ok(Self { transaction_id })
    }
}

#[derive(Debug, Clone)]
pub struct ConnectResponse {
    pub transaction_id: u32,
    pub connection_id: u64,
}

impl Wire for ConnectResponse {
    fn encode<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        Action::Connect.encode(&mut writer)?;
        self.transaction_id.encode(&mut writer)?;
        self.connection_id.encode(&mut writer)?;
        Ok(())
    }

    fn decode<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let action = Action::decode(&mut reader)?;
        if action != Action::Connect {
            return Err(invalid_data("expected action to be 'connect'"));
        }
        let transaction_id = u32::decode(&mut reader)?;
        let connection_id = u64::decode(&mut reader)?;
        Ok(Self {
            transaction_id,
            connection_id,
        })
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    #[default]
    None = 0,
    Completed = 1,
    Started = 2,
    Stopped = 3,
}

impl Wire for Event {
    fn encode<W: Write>(&self, writer: W) -> std::io::Result<()> {
        (*self as u32).encode(writer)
    }

    fn decode<R: Read>(reader: R) -> std::io::Result<Self> {
        let v = u32::decode(reader)?;
        match v {
            _ if v == Event::None as u32 => Ok(Event::None),
            _ if v == Event::Completed as u32 => Ok(Event::Completed),
            _ if v == Event::Started as u32 => Ok(Event::Started),
            _ if v == Event::Stopped as u32 => Ok(Event::Stopped),
            _ => Err(invalid_data("invalid event value")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnnounceIpv4Request {
    pub connection_id: u64,
    pub transaction_id: u32,
    pub info_hash: Sha1,
    pub peer_id: PeerId,
    pub downloaded: u64,
    pub left: u64,
    pub uploaded: u64,
    pub event: Event,
    pub ip_address: Ipv4Addr,
    pub key: u32,
    pub num_want: u32,
    pub port: u16,
}

impl Wire for AnnounceIpv4Request {
    fn encode<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.connection_id.encode(&mut writer)?;
        Action::Announce.encode(&mut writer)?;
        self.transaction_id.encode(&mut writer)?;
        self.info_hash.encode(&mut writer)?;
        self.peer_id.encode(&mut writer)?;
        self.downloaded.encode(&mut writer)?;
        self.left.encode(&mut writer)?;
        self.uploaded.encode(&mut writer)?;
        self.event.encode(&mut writer)?;
        self.ip_address.encode(&mut writer)?;
        self.key.encode(&mut writer)?;
        self.num_want.encode(&mut writer)?;
        self.port.encode(&mut writer)?;
        Ok(())
    }

    fn decode<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let connection_id = u64::decode(&mut reader)?;
        let action = Action::decode(&mut reader)?;
        let transaction_id = u32::decode(&mut reader)?;
        let info_hash = Sha1::decode(&mut reader)?;
        let peer_id = PeerId::decode(&mut reader)?;
        let downloaded = u64::decode(&mut reader)?;
        let left = u64::decode(&mut reader)?;
        let uploaded = u64::decode(&mut reader)?;
        let event = Event::decode(&mut reader)?;
        let ip_address = Ipv4Addr::decode(&mut reader)?;
        let key = u32::decode(&mut reader)?;
        let num_want = u32::decode(&mut reader)?;
        let port = u16::decode(&mut reader)?;

        if action != Action::Announce {
            return Err(invalid_data("expected action 'announce'"));
        }

        Ok(Self {
            connection_id,
            transaction_id,
            info_hash,
            peer_id,
            downloaded,
            left,
            uploaded,
            event,
            ip_address,
            key,
            num_want,
            port,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AnnounceIpv4Response {
    pub transaction_id: u32,
    pub interval: u32,
    pub leechers: u32,
    pub seeders: u32,
    pub addresses: Vec<SocketAddrV4>,
}

impl Wire for AnnounceIpv4Response {
    fn encode<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        Action::Announce.encode(&mut writer)?;
        self.transaction_id.encode(&mut writer)?;
        self.interval.encode(&mut writer)?;
        self.leechers.encode(&mut writer)?;
        for addr in &self.addresses {
            addr.encode(&mut writer)?;
        }
        Ok(())
    }

    fn decode<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let action = Action::decode(&mut reader)?;
        if action != Action::Announce {
            return Err(invalid_data("expected action to be 'announce'"));
        }
        let transaction_id = u32::decode(&mut reader)?;
        let interval = u32::decode(&mut reader)?;
        let leechers = u32::decode(&mut reader)?;
        let seeders = u32::decode(&mut reader)?;
        let mut addresses = Vec::new();
        loop {
            match SocketAddrV4::decode(&mut reader) {
                Ok(addr) => addresses.push(addr),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        break;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Ok(Self {
            transaction_id,
            interval,
            leechers,
            seeders,
            addresses,
        })
    }
}

#[derive(Debug, Clone)]
struct AnnounceParams {
    info_hash: Sha1,
    peer_id: PeerId,
    downloaded: u64,
    left: u64,
    uploaded: u64,
    event: Event,
    ip_address: Option<Ipv4Addr>,
    num_want: Option<u32>,
    port: u16,
}

#[derive(Debug)]
struct Announce {
    interval: u32,
    leechers: u32,
    seeders: u32,
    addresses: Vec<SocketAddrV4>,
}

struct TrackerUdpClient {
    socket: UdpSocket,
    connection_id: Option<u64>,
}

impl TrackerUdpClient {
    pub fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self {
            socket,
            connection_id: None,
        })
    }

    pub fn announce(&mut self, params: &AnnounceParams) -> std::io::Result<Announce> {
        let connection_id = self.connect()?;
        println!("connection id = {connection_id}");
        let request = AnnounceIpv4Request {
            connection_id,
            transaction_id: random_transaction_id(),
            info_hash: params.info_hash,
            peer_id: params.peer_id,
            downloaded: params.downloaded,
            left: params.left,
            uploaded: params.uploaded,
            event: params.event,
            ip_address: params.ip_address.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)),
            key: 0,
            num_want: params.num_want.unwrap_or(u32::MAX),
            port: params.port,
        };

        let mut buffer = [0u8; 1500];
        request.encode(Cursor::new(&mut buffer[..]))?;
        self.socket.send(&buffer[..])?;

        let n = self.socket.recv(&mut buffer)?;
        let buffer = &buffer[..n];
        let response = AnnounceIpv4Response::decode(Cursor::new(buffer))?;
        Ok(Announce {
            interval: response.interval,
            leechers: response.leechers,
            seeders: response.seeders,
            addresses: response.addresses,
        })
    }

    fn connect(&mut self) -> std::io::Result<u64> {
        if let Some(connection_id) = self.connection_id {
            Ok(connection_id)
        } else {
            let mut buffer = Vec::default();
            let request = ConnectRequest {
                transaction_id: random_transaction_id(),
            };
            request.encode(&mut buffer)?;
            self.socket.send(&buffer)?;

            buffer.resize(1500, 0);
            let n = self.socket.recv(&mut buffer)?;
            buffer.truncate(n);
            let response = ConnectResponse::decode(Cursor::new(&buffer))?;
            Ok(response.connection_id)
        }
    }
}

fn random_transaction_id() -> u32 {
    rand::random()
}

fn invalid_data(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

const HANDSHAKE_PREFIX_IDX: usize = 0;
const HANDSHAKE_PREFIX_LENGTH: usize = 20;
const HANDSHAKE_PREFIX: &[u8; HANDSHAKE_PREFIX_LENGTH] = b"\x13BitTorrent protocol";

const HANDSHAKE_RESERVED_IDX: usize = HANDSHAKE_PREFIX_LENGTH;
const HANDSHAKE_RESERVED_LENGTH: usize = 8;

const HANDSHAKE_INFOHASH_IDX: usize = HANDSHAKE_RESERVED_IDX + HANDSHAKE_RESERVED_LENGTH;
const HANDSHAKE_PEERID_IDX: usize = HANDSHAKE_INFOHASH_IDX + 20;

const HANDSHAKE_LENGTH: usize = HANDSHAKE_PREFIX_LENGTH
    + HANDSHAKE_RESERVED_LENGTH // 8 reserved bytes, currently all zero
    + 20 // 20 byte sha1 info_hash
    + 20; // 20 byte peer id

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MessageKind {
    Choke = 0,
    Unchoke = 1,
    Interested = 2,
    NotInterested = 3,
    Have = 4,
    Bitfield = 5,
    Request = 6,
    Piece = 7,
    Cancel = 8,
}

impl MessageKind {
    fn from_u8(kind: u8) -> Option<MessageKind> {
        match kind {
            _ if kind == MessageKind::Choke as u8 => Some(MessageKind::Choke),
            _ if kind == MessageKind::Unchoke as u8 => Some(MessageKind::Unchoke),
            _ if kind == MessageKind::Interested as u8 => Some(MessageKind::Interested),
            _ if kind == MessageKind::NotInterested as u8 => Some(MessageKind::NotInterested),
            _ if kind == MessageKind::Have as u8 => Some(MessageKind::Have),
            _ if kind == MessageKind::Bitfield as u8 => Some(MessageKind::Bitfield),
            _ if kind == MessageKind::Request as u8 => Some(MessageKind::Request),
            _ if kind == MessageKind::Piece as u8 => Some(MessageKind::Piece),
            _ if kind == MessageKind::Cancel as u8 => Some(MessageKind::Cancel),
            _ => None,
        }
    }

    fn to_u8(&self) -> u8 {
        *self as u8
    }
}

fn error(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

#[derive(Debug)]
struct Handshake {
    info_hash: Sha1,
    peer_id: PeerId,
}

struct HandshakeSplit<'a> {
    prefix: &'a [u8; HANDSHAKE_PREFIX_LENGTH],
    reserved: &'a [u8; HANDSHAKE_RESERVED_LENGTH],
    info_hash: &'a [u8; 20],
    peer_id: &'a [u8; 20],
}

impl<'a> HandshakeSplit<'a> {
    fn new(buf: &'a [u8; HANDSHAKE_LENGTH]) -> HandshakeSplit {
        let (prefix, buf) = buf.split_at(HANDSHAKE_PREFIX_LENGTH);
        let (reserved, buf) = buf.split_at(HANDSHAKE_RESERVED_LENGTH);
        let (info_hash, buf) = buf.split_at(20);
        let peer_id = buf;

        HandshakeSplit {
            prefix: prefix.try_into().unwrap(),
            reserved: reserved.try_into().unwrap(),
            info_hash: info_hash.try_into().unwrap(),
            peer_id: peer_id.try_into().unwrap(),
        }
    }
}

fn serialize_handshake(handshake: &Handshake) -> [u8; HANDSHAKE_LENGTH] {
    let mut buf = [0u8; HANDSHAKE_LENGTH];
    buf[0..HANDSHAKE_PREFIX_LENGTH].copy_from_slice(HANDSHAKE_PREFIX);
    buf[HANDSHAKE_INFOHASH_IDX..HANDSHAKE_INFOHASH_IDX + 20]
        .copy_from_slice(handshake.info_hash.as_bytes());
    buf[HANDSHAKE_PEERID_IDX..HANDSHAKE_PEERID_IDX + 20]
        .copy_from_slice(handshake.info_hash.as_bytes());
    buf
}

fn write_handshake<W: Write>(mut writer: W, handshake: &Handshake) -> std::io::Result<()> {
    let buf = serialize_handshake(handshake);
    writer.write_all(&buf)?;
    Ok(())
}

fn read_handshake<R: Read>(mut reader: R) -> std::io::Result<Handshake> {
    let mut buf = [0u8; HANDSHAKE_LENGTH];
    reader.read_exact(&mut buf)?;

    let split = HandshakeSplit::new(&buf);
    assert_eq!(split.prefix, HANDSHAKE_PREFIX);

    Ok(Handshake {
        info_hash: Sha1(*split.info_hash),
        peer_id: PeerId(*split.peer_id),
    })
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

// #[derive(Default, Clone)]
// pub struct Bitfield {
//     data: Vec<u8>,
//     num_pieces: u32,
// }
//
// impl std::fmt::Debug for Bitfield {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_tuple("Bitfield").field(&self.num_pieces).finish()
//     }
// }
//
// impl Bitfield {
//     fn new(mut data: Vec<u8>, num_pieces: u32) -> Self {
//         let vec_len = (num_pieces + 7) / 8;
//         data.resize(vec_len as usize, 0);
//         Self { data, num_pieces }
//     }
//
//     fn empty(num_pieces: u32) -> Self {
//         Self::new(Default::default(), num_pieces)
//     }
//
//     fn set(&mut self, index: PieceIdx) {
//         let index = u32::from(index);
//         assert!(index < self.num_pieces);
//         let byte_index = index / 8;
//         self.data[byte_index as usize] |= 1 << (index % 8);
//     }
//
//     fn unset(&mut self, index: PieceIdx) {
//         let index = u32::from(index);
//         assert!(index < self.num_pieces);
//         let byte_index = index / 8;
//         self.data[byte_index as usize] &= !(1 << (index % 8));
//     }
//
//     fn test(&self, index: u32) -> bool {
//         assert!(index < self.num_pieces);
//         let byte_index = index / 8;
//         (self.data[byte_index as usize] & 1 << (index % 8)) != 0
//     }
//
//     fn complete(&self) -> bool {
//         if !self
//             .data
//             .iter()
//             .take((self.num_pieces / 8) as usize)
//             .all(|&b| b == 0xFF)
//         {
//             return false;
//         }
//         if self.num_pieces % 8 != 0 {
//             if self.data[self.data.len() - 1] != !(1 << self.num_pieces % 8) {
//                 return false;
//             }
//         }
//         true
//     }
//
//     fn contains_missing_in(&self, other: &Self) -> bool {
//         assert_eq!(self.num_pieces, other.num_pieces);
//         for (&lhs, &rhs) in self.data.iter().zip(other.data.iter()) {
//             if lhs & !rhs != 0 {
//                 return true;
//             }
//         }
//         false
//     }
//
//     fn iter_missing_in<'s>(&'s self, other: &'s Self) -> impl Iterator<Item = PieceIdx> + 's {
//         // TODO: improve function
//         (0..self.num_pieces)
//             .map(|idx| (idx as u32, self.test(idx as u32), other.test(idx as u32)))
//             .filter(|(_, lhs, rhs)| *lhs && !*rhs)
//             .map(|(idx, _, _)| PieceIdx::from(idx))
//     }
// }

#[derive(Debug)]
enum Message {
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have {
        index: PieceIdx,
    },
    Bitfield {
        bitfield: Vec<u8>,
    },
    Request {
        index: PieceIdx,
        begin: u32,
        length: u32,
    },
    Piece {
        index: PieceIdx,
        begin: u32,
        data: Bytes,
    },
    Cancel {
        index: PieceIdx,
        begin: u32,
        length: u32,
    },
}

fn decode_message(buf: &[u8]) -> std::io::Result<Message> {
    if buf.len() < 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "read empty buffer",
        ));
    }
    let message_kind = match MessageKind::from_u8(buf[0]) {
        Some(kind) => kind,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown message kind: {}", buf[0]),
            ));
        }
    };
    let message = match message_kind {
        MessageKind::Choke => {
            // TODO: check len == 1
            Message::Choke
        }
        MessageKind::Unchoke => {
            // TODO: check len == 1
            Message::Unchoke
        }
        MessageKind::Interested => {
            // TODO: check len == 1
            Message::Interested
        }
        MessageKind::NotInterested => {
            // TODO: check len == 1
            Message::NotInterested
        }
        MessageKind::Have => {
            // TODO: check len == 5
            let index = PieceIdx::from(u32::from_be_bytes(buf[1..5].try_into().unwrap()));
            Message::Have { index }
        }
        MessageKind::Bitfield => Message::Bitfield {
            bitfield: buf[1..].to_owned(),
        },
        MessageKind::Request => {
            // TODO: check len == 13
            let index = PieceIdx::from(u32::from_be_bytes(buf[1..5].try_into().unwrap()));
            let begin = u32::from_be_bytes(buf[5..9].try_into().unwrap());
            let length = u32::from_be_bytes(buf[9..13].try_into().unwrap());
            Message::Request {
                index,
                begin,
                length,
            }
        }
        MessageKind::Piece => {
            // TODO: check len >= 9
            let index = PieceIdx::from(u32::from_be_bytes(buf[1..5].try_into().unwrap()));
            let begin = u32::from_be_bytes(buf[5..9].try_into().unwrap());
            let data = Bytes::copy_from_slice(&buf[9..]);
            Message::Piece { index, begin, data }
        }
        MessageKind::Cancel => {
            // TODO: check len == 13
            let index = PieceIdx::from(u32::from_be_bytes(buf[1..5].try_into().unwrap()));
            let begin = u32::from_be_bytes(buf[5..9].try_into().unwrap());
            let length = u32::from_be_bytes(buf[9..13].try_into().unwrap());
            Message::Request {
                index,
                begin,
                length,
            }
        }
    };
    Ok(message)
}

fn read_message<R: Read>(mut reader: R) -> std::io::Result<Message> {
    let mut buf = Vec::new();
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len);
    buf.resize(len as usize, 0);
    reader.read_exact(&mut buf)?;
    Ok(decode_message(&buf)?)
}

fn write_u32<W: Write>(mut writer: W, value: u32) -> std::io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

fn write_message_kind<W: Write>(mut writer: W, kind: MessageKind) -> std::io::Result<()> {
    writer.write_all(&[kind.to_u8()])
}

fn write_message<W: Write>(mut writer: W, message: &Message) -> std::io::Result<()> {
    match message {
        Message::Choke => {
            write_u32(&mut writer, 1)?;
            write_message_kind(&mut writer, MessageKind::Choke)
        }
        Message::Unchoke => {
            write_u32(&mut writer, 1)?;
            write_message_kind(&mut writer, MessageKind::Unchoke)
        }
        Message::Interested => {
            write_u32(&mut writer, 1)?;
            write_message_kind(&mut writer, MessageKind::Interested)
        }
        Message::NotInterested => {
            write_u32(&mut writer, 1)?;
            write_message_kind(&mut writer, MessageKind::NotInterested)
        }
        Message::Have { index } => {
            write_u32(&mut writer, 5)?;
            write_message_kind(&mut writer, MessageKind::Have)?;
            write_u32(&mut writer, u32::from(*index))?;
            Ok(())
        }
        Message::Bitfield { bitfield } => {
            write_u32(&mut writer, (bitfield.len() + 1) as u32)?;
            write_message_kind(&mut writer, MessageKind::Bitfield)?;
            writer.write_all(&bitfield)?;
            Ok(())
        }
        Message::Request {
            index,
            begin,
            length,
        } => {
            write_u32(&mut writer, 13)?;
            write_message_kind(&mut writer, MessageKind::Request)?;
            write_u32(&mut writer, u32::from(*index))?;
            write_u32(&mut writer, *begin)?;
            write_u32(&mut writer, *length)?;
            Ok(())
        }
        Message::Piece { index, begin, data } => {
            let len = 8 + data.len() as u32;
            write_u32(&mut writer, len)?;
            write_u32(&mut writer, u32::from(*index))?;
            write_u32(&mut writer, *begin)?;
            writer.write_all(&data)?;
            Ok(())
        }
        Message::Cancel {
            index,
            begin,
            length,
        } => {
            write_u32(&mut writer, 12)?;
            write_u32(&mut writer, u32::from(*index))?;
            write_u32(&mut writer, *begin)?;
            write_u32(&mut writer, *length)?;
            Ok(())
        }
    }
}

slotmap::new_key_type! {
    pub struct PieceKey;
    pub struct FileKey;
    pub struct ChunkKey;
    pub struct PeerKey;
    pub struct TrackerKey;
}

impl PieceKey {
    pub fn from_index(index: PieceIdx) -> PieceKey {
        PieceKey::from(slotmap::KeyData::from_ffi(u64::from(u32::from(index))))
    }

    pub fn to_index(&self) -> PieceIdx {
        PieceIdx::from((self.data().as_ffi() & 0xFFFFFFFF) as u32)
    }
}

const CHUNK_LENGTH: u32 = 16 * 1024;
const MAX_PEER_PENDING_CHUNKS: usize = 256;
const PEER_COUNT_LIMIT: usize = 50;

type Sender<T> = std::sync::mpsc::Sender<T>;
type Receiver<T> = std::sync::mpsc::Receiver<T>;
type TorrentSender = std::sync::mpsc::Sender<TorrentMsg>;
type TorrentReceiver = std::sync::mpsc::Receiver<TorrentMsg>;

#[derive(Debug)]
struct PeerIO {
    sender: Sender<Message>,
}

impl PeerIO {
    pub fn connect(
        key: PeerKey,
        torrent_sender: TorrentSender,
        addr: SocketAddr,
        peer_id: PeerId,
        info_hash: Sha1,
    ) -> PeerIO {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            peer_io_connect(key, receiver, torrent_sender, addr, peer_id, info_hash)
        });
        Self { sender }
    }

    pub fn accept(
        key: PeerKey,
        info: TorrentInfo,
        peer_id: PeerId,
        torrent_sender: TorrentSender,
        stream: TcpStream,
    ) -> Self {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            peer_io_accept(
                key,
                stream,
                receiver,
                torrent_sender,
                peer_id,
                info.info_hash(),
            )
        });
        Self { sender }
    }

    pub fn send(&self, message: Message) {
        // TODO: log result if it is error
        // we probably don't care if this fails since that means the threads are exiting and a peer
        // failure message has already been queued. It should never be the case that this fails but
        // a failure message is not queued.
        let _ = self.sender.send(message);
    }
}

fn peer_io_connect(
    key: PeerKey,
    receiver: Receiver<Message>,
    sender: TorrentSender,
    addr: SocketAddr,
    peer_id: PeerId,
    info_hash: Sha1,
) {
    fn try_connect(
        addr: SocketAddr,
        peer_id: PeerId,
        info_hash: Sha1,
    ) -> std::io::Result<(TcpStream, PeerId)> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_write_timeout(Some(Duration::from_secs(8)))?;
        write_handshake(&mut stream, &Handshake { info_hash, peer_id })?;
        let handshake = read_handshake(&mut stream)?;
        if handshake.info_hash != info_hash {
            return Err(std::io::Error::other("handshake info hash missmatch"));
        }
        Ok((stream, handshake.peer_id))
    }

    let (stream, remote_peer_id) = match try_connect(addr, peer_id, info_hash) {
        Ok((stream, handshake)) => (stream, handshake),
        Err(error) => {
            let _ = sender.send(TorrentMsg::PeerError { key, error });
            return;
        }
    };

    let send_result = sender.send(TorrentMsg::PeerHandshake {
        key,
        id: remote_peer_id,
    });
    if send_result.is_err() {
        return;
    }

    let stream = Arc::new(stream);
    std::thread::spawn({
        let stream = stream.clone();
        let sender = sender.clone();
        move || peer_io_writer(key, receiver, sender, stream)
    });
    peer_io_reader(key, sender, stream);
}

fn peer_io_accept(
    key: PeerKey,
    stream: TcpStream,
    receiver: Receiver<Message>,
    sender: TorrentSender,
    peer_id: PeerId,
    info_hash: Sha1,
) {
    fn try_accept(
        mut stream: TcpStream,
        peer_id: PeerId,
        info_hash: Sha1,
    ) -> std::io::Result<(TcpStream, PeerId)> {
        stream.set_write_timeout(Some(Duration::from_secs(8)))?;
        let handshake = read_handshake(&mut stream)?;
        if handshake.info_hash != info_hash {
            return Err(std::io::Error::other("handshake info hash missmatch"));
        }
        write_handshake(&mut stream, &Handshake { info_hash, peer_id })?;
        Ok((stream, handshake.peer_id))
    }

    let (stream, remote_peer_id) = match try_accept(stream, peer_id, info_hash) {
        Ok((stream, handshake)) => (stream, handshake),
        Err(error) => {
            let _ = sender.send(TorrentMsg::PeerError { key, error });
            return;
        }
    };

    let send_result = sender.send(TorrentMsg::PeerHandshake {
        key,
        id: remote_peer_id,
    });
    if send_result.is_err() {
        return;
    }

    let stream = Arc::new(stream);
    std::thread::spawn({
        let stream = stream.clone();
        let sender = sender.clone();
        move || peer_io_writer(key, receiver, sender, stream)
    });
    peer_io_reader(key, sender, stream);
}

fn peer_io_reader(key: PeerKey, sender: TorrentSender, tcp_stream: Arc<TcpStream>) {
    let mut stream = BufReader::new(&*tcp_stream);
    loop {
        match read_message(&mut stream) {
            Ok(message) => {
                if sender
                    .send(TorrentMsg::PeerMessage { key, message })
                    .is_err()
                {
                    break;
                }
            }
            Err(error) => {
                let _ = sender.send(TorrentMsg::PeerError { key, error });
                break;
            }
        }
    }

    let _ = tcp_stream.shutdown(std::net::Shutdown::Both);
}

fn peer_io_writer(
    key: PeerKey,
    receiver: Receiver<Message>,
    sender: TorrentSender,
    tcp_stream: Arc<TcpStream>,
) {
    let mut stream = BufWriter::new(&*tcp_stream);
    while let Ok(message) = receiver.recv() {
        let result = write_message(&mut stream, &message).and_then(|_| stream.flush());
        if let Err(error) = result {
            let _ = sender.send(TorrentMsg::PeerError { key, error });
            break;
        }
    }

    let _ = tcp_stream.shutdown(std::net::Shutdown::Both);
}

enum DiskIOMsg {
    ReadPiece { idx: PieceIdx },
    WritePiece { idx: PieceIdx, data: Bytes },
}

#[derive(Debug)]
struct DiskIO {
    sender: Sender<DiskIOMsg>,
}

impl DiskIO {
    pub fn new(info: TorrentInfo, torrent_sender: TorrentSender) -> Self {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || disk_io_entry(info, receiver, torrent_sender));
        Self { sender }
    }

    pub fn read_piece(&self, idx: PieceIdx) {
        self.send(DiskIOMsg::ReadPiece { idx });
    }

    pub fn write_piece(&self, idx: PieceIdx, data: Bytes) {
        self.send(DiskIOMsg::WritePiece { idx, data });
    }

    fn send(&self, msg: DiskIOMsg) {
        self.sender.send(msg).expect("disk io should not exit");
    }
}

fn disk_io_entry(info: TorrentInfo, receiver: Receiver<DiskIOMsg>, sender: TorrentSender) {
    while let Ok(msg) = receiver.recv() {
        match msg {
            DiskIOMsg::ReadPiece { idx } => match attempt_read_piece(&info, idx) {
                Ok(data) => {
                    let _ = sender.send(TorrentMsg::ReadPieceSuccess { idx, data });
                }
                Err(error) => {
                    let _ = sender.send(TorrentMsg::ReadPieceError { idx, error });
                }
            },
            DiskIOMsg::WritePiece { idx, data } => {
                for range in info.files_from_piece(idx) {
                    match attempt_write_piece(
                        &range.file.path,
                        range.file_start,
                        &data[range.piece_range()],
                    ) {
                        Ok(_) => {}
                        Err(error) => {
                            let _ = sender.send(TorrentMsg::WritePieceError { idx, error });
                        }
                    }
                }
            }
        }
    }
}

fn attempt_read_piece(info: &TorrentInfo, piece_idx: PieceIdx) -> std::io::Result<Bytes> {
    let piece_len = info.piece_length_from_index(piece_idx);

    let mut data = BytesMut::new();
    data.resize(piece_len as usize, 0);

    for range in info.files_from_piece(piece_idx) {
        let mut file = std::fs::OpenOptions::new()
            .create(false)
            .write(false)
            .read(true)
            .open(&range.file.path)?;
        file.seek(std::io::SeekFrom::Start(range.file_start))?;
        file.read_exact(&mut data[range.piece_range()])?;
    }

    Ok(data.freeze())
}

fn attempt_write_piece(path: &Path, offset: u64, data: &[u8]) -> std::io::Result<()> {
    //println!("writing piece to {path:?} at offset {offset}");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)?;
    file.seek(std::io::SeekFrom::Start(offset))?;
    file.write_all(data)?;
    Ok(())
}

enum TrackerMsg {
    Announce(AnnounceParams),
}

#[derive(Debug)]
struct TrackerIO {
    sender: Sender<TrackerMsg>,
}

impl TrackerIO {
    pub fn new(key: TrackerKey, url: String, torrent_sender: TorrentSender) -> Self {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || tracker_entry(key, url, receiver, torrent_sender));
        Self { sender }
    }

    pub fn announce(&self, params: &AnnounceParams) {
        self.send(TrackerMsg::Announce(params.clone()));
    }

    fn send(&self, msg: TrackerMsg) {
        self.sender
            .send(msg)
            .expect("tracker receiver should not exit")
    }
}

fn tracker_entry(
    key: TrackerKey,
    url: String,
    receiver: Receiver<TrackerMsg>,
    sender: TorrentSender,
) {
    const ERROR_SLEEP_DURATION: Duration = Duration::from_secs(2);

    'outer: loop {
        // empty the queue of tracker requests
        loop {
            match receiver.try_recv() {
                Ok(_) => {}
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break 'outer,
            };
        }

        let mut client = match tracker_create_client(&url) {
            Ok(client) => client,
            Err(error) => {
                let _ = sender.send(TorrentMsg::TrackerError { key, error });
                std::thread::sleep(ERROR_SLEEP_DURATION);
                continue;
            }
        };

        if let Err(error) = tracker_loop(key, &mut client, &receiver, &sender) {
            let _ = sender.send(TorrentMsg::TrackerError { key, error });
            std::thread::sleep(ERROR_SLEEP_DURATION);
            continue;
        }
    }
}

fn tracker_create_client(url: &str) -> std::io::Result<TrackerUdpClient> {
    let url = match url.strip_prefix("udp://") {
        Some(url) => url,
        None => return Err(std::io::Error::other("unsupported tracker protocol")),
    };

    let mut addrs = url.to_socket_addrs()?;
    let addr = match addrs.next() {
        Some(addr) => addr,
        None => return Err(std::io::Error::other("failed to resolve tracker url")),
    };

    TrackerUdpClient::new(addr)
}
fn tracker_loop(
    key: TrackerKey,
    client: &mut TrackerUdpClient,
    receiver: &Receiver<TrackerMsg>,
    sender: &TorrentSender,
) -> std::io::Result<()> {
    while let Ok(msg) = receiver.recv() {
        match msg {
            TrackerMsg::Announce(params) => {
                let response = client.announce(&params)?;
                let _ = sender.send(TorrentMsg::TrackerAnnounce {
                    key,
                    announce: response,
                });
            }
        }
    }
    Ok(())
}

fn listener_start(listen_addr: SocketAddr, sender: TorrentSender) -> std::io::Result<()> {
    println!("starting listener at {listen_addr}");
    let listener = TcpListener::bind(listen_addr)?;
    std::thread::spawn(move || listener_loop(listener, sender));
    Ok(())
}

fn listener_loop(listener: TcpListener, sender: TorrentSender) {
    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                println!("accepting connection from {addr}");
                if sender
                    .send(TorrentMsg::PeerConnected { addr, stream })
                    .is_err()
                {
                    break;
                }
            }
            Err(error) => {
                println!("failed to accept peer: {error}");
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkStats {
    pub download: u64,
    pub upload: u64,
    pub download_rate: u32,
    pub upload_rate: u32,
}

#[derive(Debug, Clone)]
pub struct NetworkStatsAccum {
    total_download: u64,
    total_upload: u64,
    download_rate: u32,
    upload_rate: u32,
    download_acum: u32,
    upload_acum: u32,
    last_download: Instant,
    last_upload: Instant,
    period: Duration,
}

impl NetworkStatsAccum {
    pub fn new(period: Duration) -> Self {
        Self {
            total_download: 0,
            total_upload: 0,
            download_rate: 0,
            upload_rate: 0,
            download_acum: 0,
            upload_acum: 0,
            last_download: Instant::now(),
            last_upload: Instant::now(),
            period,
        }
    }

    pub fn add_download(&mut self, num_bytes: u32) {
        self.total_download += num_bytes as u64;
        if self.last_download.elapsed() > self.period {
            self.last_download = Instant::now();
            self.download_rate = self.download_acum / self.period.as_secs() as u32;
            self.download_acum = num_bytes;
        } else {
            self.download_acum += num_bytes;
        }
    }

    pub fn add_upload(&mut self, num_bytes: u32) {
        self.total_upload += num_bytes as u64;
        if self.last_upload.elapsed() > self.period {
            self.last_upload = Instant::now();
            self.upload_rate = self.upload_acum / self.period.as_secs() as u32;
            self.upload_acum = num_bytes;
        } else {
            self.upload_acum += num_bytes;
        }
    }

    /// download rate in bytes/sec
    pub fn download_rate(&self) -> u32 {
        if self.last_download.elapsed() > self.period {
            0
        } else {
            self.download_rate
        }
    }

    /// upload rate in bytes/sec
    pub fn upload_rate(&self) -> u32 {
        if self.last_upload.elapsed() > self.period {
            0
        } else {
            self.upload_rate
        }
    }

    pub fn total_download(&self) -> u64 {
        self.total_download
    }

    pub fn total_upload(&self) -> u64 {
        self.total_upload
    }

    pub fn stats(&self) -> NetworkStats {
        NetworkStats {
            download: self.total_download(),
            upload: self.total_upload(),
            download_rate: self.download_rate(),
            upload_rate: self.upload_rate(),
        }
    }
}

impl Default for NetworkStatsAccum {
    fn default() -> Self {
        Self::new(Duration::from_secs_f64(1.5))
    }
}

#[derive(Debug)]
enum TorrentMsg {
    PeerHandshake {
        key: PeerKey,
        id: PeerId,
    },
    PeerMessage {
        key: PeerKey,
        message: Message,
    },
    PeerConnected {
        addr: SocketAddr,
        stream: TcpStream,
    },
    PeerError {
        key: PeerKey,
        error: std::io::Error,
    },
    TrackerAnnounce {
        key: TrackerKey,
        announce: Announce,
    },
    TrackerError {
        key: TrackerKey,
        error: std::io::Error,
    },
    ConnectToPeer {
        addr: SocketAddr,
    },
    ReadPieceSuccess {
        idx: PieceIdx,
        data: Bytes,
    },
    ReadPieceError {
        idx: PieceIdx,
        error: std::io::Error,
    },
    WritePieceError {
        idx: PieceIdx,
        error: std::io::Error,
    },
    ChangeMode {
        mode: TorrentMode,
    },
    NetworkStats {
        res: Sender<NetworkStats>,
    },
    Completed {
        res: Sender<bool>,
    },
}

#[derive(Debug)]
struct FileState {
    path: PathBuf,
    offset: u64,
    length: u64,
}

#[derive(Debug)]
struct PieceState {
    hash: Sha1,
    length: u32,
    chunks: Vec<ChunkKey>,

    /// are we waiting to read this piece from disk
    disk_requested: bool,
}

#[derive(Debug)]
struct ChunkState {
    piece: PieceKey,
    /// offset relative to piece
    offset: u32,
    length: u32,
    assigned_peer: Option<PeerKey>,
    data: Option<Bytes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerRequest {
    piece: PieceIdx,
    begin: u32,
    length: u32,
}

#[derive(Debug)]
struct PeerState {
    id: PeerId,
    io: PeerIO,
    addr: SocketAddr,
    handshake_received: bool,
    /// have we received the bitfield from the remote peer?
    /// if the first message is not the bitfield, then it is implied that it is empty
    bitfield_received: bool,
    bitfield: PieceBitfield,
    /// are we chocked by the peer
    remote_choke: bool,
    /// are we choking the peer
    local_choke: bool,
    /// is the peer interested in us
    remote_interested: bool,
    /// are we interested in the peer
    local_interested: bool,
    pending_chunks: Vec<ChunkKey>,
    remote_requests: Vec<PeerRequest>,
}

impl PeerState {
    pub fn new(io: PeerIO, addr: SocketAddr) -> Self {
        Self {
            id: Default::default(),
            io,
            addr,
            handshake_received: false,
            bitfield_received: false,
            bitfield: Default::default(),
            remote_choke: true,
            local_choke: true,
            remote_interested: false,
            local_interested: false,
            pending_chunks: Default::default(),
            remote_requests: Default::default(),
        }
    }
}

#[derive(Debug)]
struct TrackerState {
    url: String,
    io: TrackerIO,
    next_announce: Instant,
    status: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TorrentMode {
    Starting,
    Checking,
    Running,
    Paused,
    Failed,
}

#[derive(Debug)]
struct TorrentState {
    id: PeerId,
    mode: TorrentMode,
    config: TorrentConfig,
    info: TorrentInfo,
    sender: TorrentSender,
    receiver: TorrentReceiver,
    disk_io: DiskIO,
    queue: VecDeque<TorrentMsg>,
    bitfield: PieceBitfield,
    /// track which pieces we have read (successfully or not) while checking the torrent
    checking_bitfield: PieceBitfield,
    files: SlotMap<FileKey, FileState>,
    pieces: SecondaryMap<PieceKey, PieceState>,
    chunks: SlotMap<ChunkKey, ChunkState>,
    peers: SlotMap<PeerKey, PeerState>,
    trackers: SlotMap<TrackerKey, TrackerState>,
    network_stats: NetworkStatsAccum,
    last_tick: Instant,
}

impl TorrentState {
    pub fn new(info: TorrentInfo, config: TorrentConfig) -> Self {
        let mut pieces = SecondaryMap::<PieceKey, PieceState>::default();
        let mut chunks = SlotMap::<ChunkKey, ChunkState>::default();
        let mut files = SlotMap::<FileKey, FileState>::default();
        let mut file_keys = Vec::default();

        {
            let mut current_offset = 0;
            let parent_path = PathBuf::from(info.name());
            for file in info.files() {
                let path = parent_path.join(PathBuf::from(file.path.clone()));
                let file_key = files.insert(FileState {
                    path,
                    offset: current_offset,
                    length: file.length,
                });
                file_keys.push(file_key);
                current_offset += file.length;
            }
        }

        for (index, &hash) in info.piece_indices().zip(info.pieces()) {
            let piece_key = PieceKey::from_index(index);
            let piece_length = info.piece_length_from_index(index);
            let num_chunks = (piece_length + CHUNK_LENGTH - 1) / CHUNK_LENGTH;
            pieces.insert(
                piece_key,
                PieceState {
                    hash,
                    length: piece_length,
                    chunks: Default::default(),
                    disk_requested: false,
                },
            );
            assert_eq!(piece_key.to_index(), index);

            let piece_chunks = {
                let mut piece_chunks = Vec::with_capacity(num_chunks as usize);
                let mut rem_piece_length = piece_length;
                for i in 0..num_chunks {
                    let chunk_key = chunks.insert(ChunkState {
                        piece: piece_key,
                        offset: CHUNK_LENGTH * i,
                        length: rem_piece_length.min(CHUNK_LENGTH),
                        assigned_peer: Default::default(),
                        data: Default::default(),
                    });
                    rem_piece_length = rem_piece_length.saturating_sub(CHUNK_LENGTH);
                    piece_chunks.push(chunk_key);
                }
                piece_chunks
            };

            pieces[piece_key].chunks = piece_chunks;
        }

        let (sender, receiver) = std::sync::mpsc::channel();
        let bitfield = PieceBitfield::with_size(info.pieces_count());
        let checking_bitfield = PieceBitfield::with_size(info.pieces_count());
        let disk_io = DiskIO::new(info.clone(), sender.clone());
        Self {
            id: Default::default(),
            mode: TorrentMode::Starting,
            config,
            info,
            sender,
            receiver,
            disk_io,
            queue: Default::default(),
            bitfield,
            checking_bitfield,
            files,
            pieces,
            chunks,
            peers: Default::default(),
            trackers: Default::default(),
            network_stats: Default::default(),
            last_tick: Instant::now(),
        }
    }

    pub fn queue_message(&mut self, message: TorrentMsg) {
        self.queue.push_back(message);
    }

    pub fn process(&mut self) {
        while let Some(message) = self.queue.pop_front() {
            self.process_message(message);
        }
        if self.last_tick.elapsed() > Duration::from_secs(1) {
            self.last_tick = Instant::now();
            self.process_tick();
        }
    }

    pub fn check(&mut self) {
        self.mode = TorrentMode::Checking;
        self.disconnect_peers();
        self.bitfield.clear();
        println!("started checking torrent");

        for piece_idx in self.info.piece_indices() {
            self.disk_io.read_piece(piece_idx);
        }
    }

    pub fn process_message(&mut self, message: TorrentMsg) {
        match message {
            TorrentMsg::PeerHandshake { key, id } => self.process_peer_handshake(key, id),
            TorrentMsg::PeerMessage { key, message } => self.process_peer_message(key, message),
            TorrentMsg::PeerConnected { addr, stream } => self.process_peer_connected(addr, stream),
            TorrentMsg::PeerError { key, error } => self.process_peer_error(key, error),
            TorrentMsg::TrackerAnnounce { key, announce } => {
                self.process_tracker_announce(key, announce)
            }
            TorrentMsg::TrackerError { key, error } => self.process_tracker_error(key, error),
            TorrentMsg::ConnectToPeer { addr } => self.process_connect_to_peer(addr),
            TorrentMsg::ReadPieceSuccess { idx, data } => {
                self.process_read_piece_success(idx, data)
            }
            TorrentMsg::ReadPieceError { idx, error } => self.process_read_piece_error(idx, error),
            TorrentMsg::WritePieceError { idx, error } => {
                self.process_write_piece_error(idx, error)
            }
            TorrentMsg::ChangeMode { mode } => todo!(),
            TorrentMsg::NetworkStats { res } => {
                let stats = self.network_stats.stats();
                let _ = res.send(stats);
            }
            TorrentMsg::Completed { res } => {
                let completed = self.bitfield.complete();
                let _ = res.send(completed);
            }
        }
    }

    pub fn process_tick(&mut self) {
        //println!("tick");
        if self.mode == TorrentMode::Running {
            self.check_peer_interests();
            self.request_chunks();

            if self.config.use_trackers {
                self.trackers_announce();
            }
        }
    }

    fn process_peer_handshake(&mut self, key: PeerKey, id: PeerId) {
        let peer = match self.peers.get_mut(key) {
            Some(peer) => peer,
            None => return,
        };

        if peer.handshake_received {
            self.disconnect_peer(key);
            return;
        }

        println!("received handshake");
        peer.handshake_received = true;
        peer.id = id;
    }

    fn process_peer_message(&mut self, key: PeerKey, message: Message) {
        let peer = match self.peers.get_mut(key) {
            Some(peer) => peer,
            None => return,
        };

        if !peer.handshake_received {
            println!("received peer message before handshake");
            self.disconnect_peer(key);
            return;
        }

        if let Message::Bitfield { bitfield } = message {
            println!("received bitfield");
            if peer.bitfield_received {
                println!("received duplicate peer bitfield");
                self.disconnect_peer(key);
                return;
            }
            peer.bitfield_received = true;
            peer.bitfield = PieceBitfield::from_vec(bitfield, self.info.pieces_count());
        } else {
            if !peer.bitfield_received {
                println!("received peer message before bitfield, assuming empty bitfield");
                peer.bitfield_received = true;
                peer.bitfield = PieceBitfield::with_size(self.info.pieces_count());
            }

            match message {
                Message::Choke => {
                    println!("peer choked");
                    peer.remote_choke = true;
                    self.peer_cancel_all_chunks(key);
                }
                Message::Unchoke => {
                    println!("peer unchoked");
                    peer.remote_choke = false
                }
                Message::Interested => {
                    println!("peer interested");
                    peer.remote_interested = true
                }
                Message::NotInterested => {
                    println!("peer not interested");
                    peer.remote_interested = false
                }
                Message::Have { index } => self.process_peer_have(key, index),
                Message::Bitfield { .. } => unreachable!(),
                Message::Request {
                    index,
                    begin,
                    length,
                } => self.process_peer_request(key, index, begin, length),
                Message::Piece { index, begin, data } => {
                    let piece_key = PieceKey::from_index(index);
                    if !self.pieces.contains_key(piece_key) {
                        println!("peer sent Piece message with invalid piece index");
                        self.disconnect_peer(key);
                        return;
                    }

                    let mut ckey = None;
                    for &chunk_key in peer.pending_chunks.iter() {
                        let chunk = &self.chunks[chunk_key];
                        if chunk.piece == piece_key
                            && chunk.offset == begin
                            && chunk.length as usize == data.len()
                        {
                            ckey = Some(chunk_key);
                            break;
                        }
                    }

                    match ckey {
                        Some(chunk_key) => {
                            self.process_received_chunk(key, chunk_key, data);
                        }
                        None => {
                            println!("received unrequest piece from peer");
                            // NOTE: don't disconnect here since we might have sent a Cancel
                            // message that the peer did not receive before sending us the piece.
                            return;
                        }
                    }
                }
                Message::Cancel {
                    index,
                    begin,
                    length,
                } => self.process_peer_cancel(key, index, begin, length),
            }
        }
    }

    fn process_peer_connected(&mut self, addr: SocketAddr, stream: TcpStream) {
        if self.peer_with_addr_exists(addr) {
            // TODO: log warn
            println!("peer with same addr is already connected: {addr}");
            return;
        }

        let info = self.info.clone();
        let sender = self.sender.clone();
        let peer_id = self.id;
        self.peers.insert_with_key(move |key| {
            let peer_io = PeerIO::accept(key, info, peer_id, sender, stream);
            PeerState::new(peer_io, addr)
        });
    }

    fn process_peer_have(&mut self, peer_key: PeerKey, piece_idx: PieceIdx) {
        let peer = &mut self.peers[peer_key];
        let piece_key = PieceKey::from_index(piece_idx);
        if !self.pieces.contains_key(piece_key) {
            println!("peer sent Have message with invalid piece index");
            self.disconnect_peer(peer_key);
            return;
        }
        peer.bitfield.set_piece(piece_idx);
    }

    fn process_peer_request(
        &mut self,
        peer_key: PeerKey,
        piece_idx: PieceIdx,
        begin: u32,
        length: u32,
    ) {
        if !self.info.piece_request_valid(piece_idx, begin, length) {
            self.disconnect_peer(peer_key);
            return;
        }
        let request = PeerRequest {
            piece: piece_idx,
            begin,
            length,
        };
        let peer = &mut self.peers[peer_key];
        peer.remote_requests.push(request);
        self.disk_request_piece(piece_idx);
    }

    fn process_peer_cancel(
        &mut self,
        peer_key: PeerKey,
        piece_idx: PieceIdx,
        begin: u32,
        length: u32,
    ) {
        if !self.info.piece_request_valid(piece_idx, begin, length) {
            self.disconnect_peer(peer_key);
            return;
        }
        let request = PeerRequest {
            piece: piece_idx,
            begin,
            length,
        };
        let peer = &mut self.peers[peer_key];
        peer.remote_requests.retain(|r| r != &request);
    }

    fn process_peer_error(&mut self, key: PeerKey, error: std::io::Error) {
        let addr = match self.peers.get(key) {
            Some(peer) => peer.addr,
            None => return,
        };
        println!("peer {addr} failed: {error}");
        self.disconnect_peer(key);
    }

    fn process_tracker_announce(&mut self, key: TrackerKey, announce: Announce) {
        let tracker = match self.trackers.get_mut(key) {
            Some(tracker) => tracker,
            None => return,
        };

        tracker.next_announce = Instant::now() + Duration::from_secs(u64::from(announce.interval));
        tracker.status = format!("ok");

        self.process_tracker_address_list(announce.addresses.into_iter().map(From::from).collect());
    }

    fn peers_broadcast_have(&mut self, piece_idx: PieceIdx) {
        for peer in self.peers.values() {
            peer.io.send(Message::Have { index: piece_idx });
        }
    }

    fn process_tracker_address_list(&mut self, mut addrs: Vec<SocketAddr>) {
        println!("received peer list: {:#?}", addrs);
        while self.peers.len() < PEER_COUNT_LIMIT {
            let addr = match addrs.pop() {
                Some(addr) => addr,
                None => break,
            };
            self.process_connect_to_peer(addr);
        }
    }

    fn process_tracker_error(&mut self, key: TrackerKey, error: std::io::Error) {
        let tracker = match self.trackers.get_mut(key) {
            Some(tracker) => tracker,
            None => return,
        };

        tracker.next_announce = Instant::now() + Duration::from_secs(15);
        tracker.status = format!("error: {error}");
    }

    fn process_connect_to_peer(&mut self, addr: SocketAddr) {
        println!("received request to connect to peer at {addr}");
        if self.mode != TorrentMode::Running {
            println!("can't add peer while mode is not running");
            return;
        }

        if self.peer_with_addr_exists(addr) {
            println!("peer with addr {addr} already exists, not connecting");
            return;
        }

        self.peers.insert_with_key(|key| {
            let peer_io = PeerIO::connect(
                key,
                self.sender.clone(),
                addr,
                self.id,
                self.info.info_hash(),
            );
            PeerState::new(peer_io, addr)
        });
    }

    fn process_received_chunk(&mut self, peer_key: PeerKey, chunk_key: ChunkKey, data: Bytes) {
        //println!("received chunk");

        let peer = &mut self.peers[peer_key];
        let chunk = &mut self.chunks[chunk_key];
        let piece_key = chunk.piece;
        assert_eq!(chunk.assigned_peer, Some(peer_key));
        assert!(chunk.data.is_none());

        let data_len = data.len() as u32;
        let pending_chunk_idx = peer
            .pending_chunks
            .iter()
            .position(|&k| k == chunk_key)
            .expect("peer should have pending chunk");
        peer.pending_chunks.swap_remove(pending_chunk_idx);
        chunk.data = Some(data);

        self.network_stats.add_download(data_len);
        self.attempt_finalize_piece(piece_key);
        self.request_chunks_from(peer_key);
    }

    fn process_read_piece_success(&mut self, piece_idx: PieceIdx, data: Bytes) {
        if self.mode == TorrentMode::Checking {
            self.checking_piece_read_success(piece_idx, data);
        } else {
            self.peer_serve_pending_requests_for_piece(piece_idx, data);
        }
    }

    fn process_read_piece_error(&mut self, piece_idx: PieceIdx, error: std::io::Error) {
        if self.mode == TorrentMode::Checking {
            self.checking_piece_read_failure(piece_idx, error);
        } else {
            println!("TODO: FAILED TO READ PIECE FROM DISK {piece_idx} {error}");
        }
    }

    fn process_write_piece_error(&mut self, piece_idx: PieceIdx, error: std::io::Error) {
        println!("failed to write piece {piece_idx}: {error}");
        self.bitfield.unset_piece(piece_idx);
    }

    fn checking_piece_read_success(&mut self, piece_idx: PieceIdx, data: Bytes) {
        self.checking_bitfield.set_piece(piece_idx);
        let hash = Sha1::hash(&data);
        let expected_hash = self.info.piece_hash(piece_idx).expect("piece must exist");
        if hash == expected_hash {
            self.bitfield.set_piece(piece_idx);
        } else {
            println!("hash check failed");
        }
        self.checking_try_finish();
    }

    fn checking_piece_read_failure(&mut self, piece_idx: PieceIdx, error: std::io::Error) {
        self.checking_bitfield.set_piece(piece_idx);
        self.checking_try_finish();
    }

    fn checking_try_finish(&mut self) {
        println!(
            "checking: {}/{}",
            self.checking_bitfield.num_set(),
            self.checking_bitfield.len()
        );
        if !self.checking_bitfield.complete() {
            return;
        }
        println!("done checking torrent");
        self.mode = TorrentMode::Running;
    }

    fn peer_serve_pending_requests_for_piece(&mut self, piece_idx: PieceIdx, data: Bytes) {
        let mut requests = Vec::default();
        for peer in self.peers.values_mut() {
            peer.remote_requests.retain(|r| {
                if r.piece == piece_idx {
                    requests.push(*r);
                    false
                } else {
                    true
                }
            });

            for request in requests.drain(..) {
                let message = Message::Piece {
                    index: piece_idx,
                    begin: request.begin,
                    data: data
                        .slice(request.begin as usize..(request.begin + request.length) as usize),
                };
                peer.io.send(message);
            }
        }
    }

    fn trackers_add_default(&mut self) {
        let urls = extract_tracker_urls(&self.info);
        for url in urls {
            self.tracker_add(url);
        }
    }

    fn tracker_with_url_exists(&self, url: &str) -> bool {
        self.trackers.values().any(|t| t.url == url)
    }

    fn tracker_add(&mut self, url: String) {
        if self.tracker_with_url_exists(&url) {
            return;
        }

        println!("adding tracker {url}");
        self.trackers.insert_with_key({
            let sender = self.sender.clone();
            move |key| TrackerState {
                url: url.clone(),
                io: TrackerIO::new(key, url, sender),
                next_announce: Instant::now(),
                status: Default::default(),
            }
        });
    }

    fn trackers_announce(&mut self) {
        let now = Instant::now();
        let mut trackers = Vec::new();
        for (key, tracker) in self.trackers.iter_mut() {
            if tracker.next_announce < now {
                trackers.push(key);
            }
        }

        let params = AnnounceParams {
            info_hash: self.info.info_hash(),
            peer_id: self.id,
            downloaded: 0,
            left: 0,
            uploaded: 0,
            event: Event::None,
            ip_address: None,
            num_want: None,
            port: 0,
        };

        for key in trackers {
            self.tracker_announce(key, &params);
        }
    }

    fn tracker_announce(&mut self, key: TrackerKey, params: &AnnounceParams) {
        let tracker = &mut self.trackers[key];
        tracker.io.announce(params);
        tracker.next_announce = Instant::now() + Duration::from_secs(300);
    }

    fn disk_request_piece(&mut self, piece_idx: PieceIdx) {
        let piece_key = PieceKey::from_index(piece_idx);
        let piece = &mut self.pieces[piece_key];
        if !piece.disk_requested {
            piece.disk_requested = true;
            self.disk_io.read_piece(piece_idx);
        }
    }

    fn attempt_finalize_piece(&mut self, piece_key: PieceKey) {
        let piece = &self.pieces[piece_key];
        let complete = piece
            .chunks
            .iter()
            .all(|&key| self.chunks[key].data.is_some());

        if !complete {
            return;
        }

        let mut data = BytesMut::with_capacity(piece.length as usize);
        for &chunk_key in piece.chunks.iter() {
            let chunk = &mut self.chunks[chunk_key];
            let chunk_data = chunk.data.take().unwrap(); // Safety: we know it is present from
                                                         // above
            data.extend_from_slice(&chunk_data);
        }
        let data = data.freeze();

        // TODO: move this off thread, it is a bottleneck.
        let hash = Sha1::hash(&data);
        if hash == piece.hash {
            let piece_index = piece_key.to_index();
            self.bitfield.set_piece(piece_index);
            self.disk_io.write_piece(piece_index, data);
            self.peers_broadcast_have(piece_index);
            //println!("finalized piece {piece_index}");
        } else {
            for &chunk_key in piece.chunks.iter() {
                let chunk = &mut self.chunks[chunk_key];
                chunk.assigned_peer = None;
                chunk.data = None;
            }
        }
    }

    fn check_peer_interests(&mut self) {
        for (_peer_key, peer) in self.peers.iter_mut() {
            if !peer.bitfield_received {
                continue;
            }

            let target_interest = peer.bitfield.contains_missing_in(&self.bitfield);
            let current_interest = peer.local_interested;
            if target_interest != current_interest {
                println!("updating interest {current_interest} -> {target_interest}");
                peer.local_interested = target_interest;
                if target_interest {
                    peer.io.send(Message::Interested);
                } else {
                    peer.io.send(Message::NotInterested);
                }
            }
        }
    }

    fn request_chunks(&mut self) {
        let mut candidate_peers = Vec::new();
        for (peer_key, peer) in self.peers.iter() {
            if peer.local_interested && !peer.remote_choke {
                candidate_peers.push(peer_key);
            }
        }

        for peer_key in candidate_peers {
            self.request_chunks_from(peer_key);
        }
    }

    fn request_chunks_from(&mut self, peer_key: PeerKey) {
        let peer = &mut self.peers[peer_key];
        let mut missing_iter = self.bitfield.missing_pieces_in(&peer.bitfield);
        while peer.pending_chunks.len() < MAX_PEER_PENDING_CHUNKS {
            let piece_idx = match missing_iter.next() {
                Some(idx) => idx,
                None => break,
            };
            let piece_key = PieceKey::from_index(piece_idx);
            let piece = &self.pieces[piece_key];
            for &chunk_key in piece.chunks.iter() {
                let chunk = &mut self.chunks[chunk_key];
                if chunk.assigned_peer.is_some() {
                    continue;
                }

                //println!("requesting chunk from peer");
                chunk.assigned_peer = Some(peer_key);
                peer.pending_chunks.push(chunk_key);
                peer.io.send(request_message_from_chunk(chunk));
            }
        }
    }

    fn peer_cancel_all_chunks(&mut self, peer_key: PeerKey) {
        let peer = &mut self.peers[peer_key];
        for chunk_key in peer.pending_chunks.drain(..) {
            let chunk = &mut self.chunks[chunk_key];
            assert_eq!(chunk.assigned_peer, Some(peer_key));
            self.chunks[chunk_key].assigned_peer = None;
        }
    }

    fn disconnect_peers(&mut self) {
        let keys = self.peers.keys().collect::<Vec<_>>();
        for key in keys {
            self.disconnect_peer(key);
        }
    }

    fn disconnect_peer(&mut self, peer_key: PeerKey) {
        if !self.peers.contains_key(peer_key) {
            return;
        }

        let peer_addr = self.peers[peer_key].addr;
        println!("disconnecting peer {peer_addr}");

        self.peer_cancel_all_chunks(peer_key);
        self.peers.remove(peer_key);
    }

    fn peer_with_addr_exists(&self, addr: SocketAddr) -> bool {
        self.peers.values().any(|p| p.addr == addr)
    }
}

fn request_message_from_chunk(chunk: &ChunkState) -> Message {
    Message::Request {
        index: chunk.piece.to_index(),
        begin: chunk.offset,
        length: chunk.length,
    }
}

#[derive(Debug)]
struct TorrentConfig {
    use_trackers: bool,
    listen: Option<SocketAddr>,
}

impl Default for TorrentConfig {
    fn default() -> Self {
        Self {
            use_trackers: true,
            listen: None,
        }
    }
}

#[derive(Clone)]
struct Torrent {
    sender: TorrentSender,
}

impl Torrent {
    pub fn new(info: TorrentInfo) -> Self {
        Self::new_with(info, Default::default())
    }

    pub fn new_with(info: TorrentInfo, config: TorrentConfig) -> Self {
        let listen_addr = config.listen;
        let state = TorrentState::new(info, config);
        let sender = state.sender.clone();
        std::thread::spawn(move || torrent_entry(state));
        if let Some(addr) = listen_addr {
            let sender = sender.clone();
            listener_start(addr, sender).unwrap();
        }
        Self { sender }
    }

    pub fn connect_to_peer(&self, addr: SocketAddr) {
        self.send(TorrentMsg::ConnectToPeer { addr });
    }

    pub fn network_stats(&self) -> NetworkStats {
        let (sender, receiver) = std::sync::mpsc::channel();
        self.send(TorrentMsg::NetworkStats { res: sender });
        receiver.recv().unwrap()
    }

    pub fn completed(&self) -> bool {
        let (sender, receiver) = std::sync::mpsc::channel();
        self.send(TorrentMsg::Completed { res: sender });
        receiver.recv().unwrap()
    }

    pub fn wait_until_completed(&self) {
        while !self.completed() {
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    fn send(&self, message: TorrentMsg) {
        self.sender
            .send(message)
            .expect("torrent loop should never exit while sender is alive")
    }
}

fn torrent_entry(mut state: TorrentState) {
    state.trackers_add_default();
    state.check();
    loop {
        let result = state.receiver.recv_timeout(Duration::from_secs(1));
        match result {
            Ok(msg) => state.queue_message(msg),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        state.process();
    }
}

pub struct ByteDisplay(u64);

impl std::fmt::Display for ByteDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (n, suffix) = if self.0 > 1024 * 1024 * 1024 {
            (self.0 as f64 / (1024.0 * 1024.0 * 1024.0), "GiB")
        } else if self.0 > 1024 * 1024 {
            (self.0 as f64 / (1024.0 * 1024.0), "MiB")
        } else if self.0 > 1024 {
            (self.0 as f64 / 1024.0, "KiB")
        } else {
            (self.0 as f64, "B")
        };
        write!(f, "{n} {suffix}")
    }
}

pub struct ByteRateDisplay(u64);

impl std::fmt::Display for ByteRateDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (n, suffix) = if self.0 > 1024 * 1024 * 1024 {
            (self.0 as f64 / (1024.0 * 1024.0 * 1024.0), "GiB/s")
        } else if self.0 > 1024 * 1024 {
            (self.0 as f64 / (1024.0 * 1024.0), "MiB/s")
        } else if self.0 > 1024 {
            (self.0 as f64 / 1024.0, "KiB/s")
        } else {
            (self.0 as f64, "B/s")
        };
        write!(f, "{n} {suffix}")
    }
}

fn extract_tracker_urls(info: &TorrentInfo) -> Vec<String> {
    if info.trackers().is_empty() {
        vec![info.announce().clone()]
    } else {
        info.trackers().iter().cloned().collect()
    }
}

fn extract_udp_tracker_addresses(info: &Metainfo) -> Vec<SocketAddr> {
    fn try_add_addr(out: &mut Vec<SocketAddr>, url: &str) {
        if let Some(addr_str) = url.strip_prefix("udp://") {
            if let Ok(mut addrs) = addr_str.to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    out.push(addr);
                }
            }
        }
    }

    let mut addrs = Vec::new();
    if info.announce_list.is_empty() {
        try_add_addr(&mut addrs, &info.announce);
    } else {
        for group in info.announce_list.iter() {
            for url in group.iter() {
                try_add_addr(&mut addrs, url);
            }
        }
    }
    addrs
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(default_value = "bunny.torrent")]
    torrent: String,

    #[clap(long)]
    peers: Vec<SocketAddr>,

    #[clap(long)]
    listen: Option<SocketAddr>,

    #[clap(long)]
    no_trackers: bool,

    #[clap(long)]
    seed: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let content = std::fs::read(&args.torrent).unwrap();
    let torrent_info = TorrentInfo::decode(&content)?;
    println!("{torrent_info:#?}");
    let torrent = Torrent::new_with(
        torrent_info,
        TorrentConfig {
            use_trackers: !args.no_trackers,
            listen: args.listen,
            ..Default::default()
        },
    );
    //torrent.connect_to_peer("127.0.0.1:51413".parse()?);
    std::thread::sleep(Duration::from_secs(2));
    for peer in args.peers {
        torrent.connect_to_peer(peer);
    }
    while !torrent.completed() || args.seed {
        let stats = torrent.network_stats();
        println!(
            "Download: {}\tUpload: {}\t - {}",
            ByteRateDisplay(u64::from(stats.download_rate)),
            ByteRateDisplay(u64::from(stats.upload_rate)),
            ByteDisplay(u64::from(stats.download))
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

fn list_tracker_peers() {
    let content = std::fs::read("hungergames.torrent").unwrap();
    println!("{:#?}", bencode::decode_value(&content).unwrap());

    let metainfo = bencode::decode::<Metainfo>(&content).unwrap();
    println!("{:#?}", metainfo);
    // tracker.torrent.eu.org:451/announce

    println!("{}", metainfo.announce);

    let mut sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.connect("tracker.torrent.eu.org:451").unwrap();

    let mut buf = Vec::with_capacity(1024);
    let req = ConnectRequest {
        transaction_id: 0xdeadbeef,
    };
    req.encode(&mut buf).unwrap();
    sock.send(&buf).unwrap();

    buf.clear();
    buf.resize(1024, 0);
    let n = sock.recv(&mut buf).unwrap();
    buf.resize(n, 0);
    let res = ConnectResponse::decode(std::io::Cursor::new(&buf)).unwrap();
    println!("response = {:#?}", res);

    let peer_id = PeerId::default();
    let req = AnnounceIpv4Request {
        connection_id: res.connection_id,
        transaction_id: res.transaction_id,
        info_hash: metainfo.info_hash,
        peer_id,
        downloaded: 0,
        left: metainfo.info.length,
        uploaded: 0,
        event: Event::None,
        ip_address: Ipv4Addr::new(0, 0, 0, 0),
        key: 0,
        num_want: 50,
        port: 61182,
    };

    buf.clear();
    req.encode(&mut buf).unwrap();
    sock.send(&buf).unwrap();

    buf.resize(1024, 0);
    let n = sock.recv(&mut buf).unwrap();
    buf.resize(n, 0);
    let res = AnnounceIpv4Response::decode(std::io::Cursor::new(&buf)).unwrap();
    println!("{:#?}", res);
}

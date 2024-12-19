use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket},
    sync::Arc,
};

use serde::Serialize;
use sha1::digest::Output;
use slotmap::SlotMap;

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

#[derive(Debug)]
struct Metainfo {
    announce: String,
    announce_list: Vec<Vec<String>>,
    info: Info,
    info_hash: Sha1,
}

#[derive(Debug)]
struct InfoFile {
    path: String,
    length: u64,
}

#[derive(Debug)]
struct Info {
    name: String,
    piece_length: u64,
    length: u64,
    pieces: Vec<Sha1>,
    files: Vec<InfoFile>,
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
        Ok(Self {
            announce,
            announce_list,
            info,
            info_hash,
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
    fn from_u8(kind: u8) -> MessageKind {
        match kind {
            _ if kind == MessageKind::Choke as u8 => MessageKind::Choke,
            _ if kind == MessageKind::Unchoke as u8 => MessageKind::Unchoke,
            _ if kind == MessageKind::Interested as u8 => MessageKind::Interested,
            _ if kind == MessageKind::NotInterested as u8 => MessageKind::NotInterested,
            _ if kind == MessageKind::Have as u8 => MessageKind::Have,
            _ if kind == MessageKind::Bitfield as u8 => MessageKind::Bitfield,
            _ if kind == MessageKind::Request as u8 => MessageKind::Request,
            _ if kind == MessageKind::Piece as u8 => MessageKind::Piece,
            _ if kind == MessageKind::Cancel as u8 => MessageKind::Cancel,
            _ => panic!("invalid message kind"),
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

#[derive(Clone)]
struct Buffer(Arc<[u8]>);

impl std::fmt::Debug for Buffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Buffer").field(&self.0.len()).finish()
    }
}

impl Buffer {
    fn new(buf: &[u8]) -> Self {
        let mut v = Vec::new();
        v.extend_from_slice(buf);
        Self(Arc::from(v.into_boxed_slice()))
    }
}

#[derive(Clone)]
struct Bitfield(Arc<[u8]>);

impl std::fmt::Debug for Bitfield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bitfield").field(&self.0.len()).finish()
    }
}

impl Bitfield {
    fn new(buf: &[u8]) -> Self {
        let mut v = Vec::new();
        v.extend_from_slice(buf);
        Self(Arc::from(v.into_boxed_slice()))
    }
}

#[derive(Debug)]
enum Message {
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have {
        index: u32,
    },
    Bitfield {
        bitfield: Bitfield,
    },
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        data: Buffer,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
}

fn decode_message(buf: &[u8]) -> Message {
    if buf.len() < 1 {
        panic!("cannot read message type of empty message");
    }
    let message_kind = MessageKind::from_u8(buf[0]);
    match message_kind {
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
            let index = u32::from_be_bytes(buf[1..5].try_into().unwrap());
            Message::Have { index }
        }
        MessageKind::Bitfield => Message::Bitfield {
            bitfield: Bitfield::new(&buf[1..]),
        },
        MessageKind::Request => {
            // TODO: check len == 13
            let index = u32::from_be_bytes(buf[1..5].try_into().unwrap());
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
            let index = u32::from_be_bytes(buf[1..5].try_into().unwrap());
            let begin = u32::from_be_bytes(buf[5..9].try_into().unwrap());
            let data = Buffer::new(&buf[9..]);
            Message::Piece { index, begin, data }
        }
        MessageKind::Cancel => {
            // TODO: check len == 13
            let index = u32::from_be_bytes(buf[1..5].try_into().unwrap());
            let begin = u32::from_be_bytes(buf[5..9].try_into().unwrap());
            let length = u32::from_be_bytes(buf[9..13].try_into().unwrap());
            Message::Request {
                index,
                begin,
                length,
            }
        }
    }
}

fn read_message<R: Read>(mut reader: R) -> std::io::Result<Message> {
    let mut buf = Vec::new();
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len);
    buf.resize(len as usize, 0);
    reader.read_exact(&mut buf)?;
    Ok(decode_message(&buf))
}

fn write_u32<W: Write>(mut writer: W, value: u32) -> std::io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

fn write_message<W: Write>(mut writer: W, message: &Message) -> std::io::Result<()> {
    match message {
        Message::Choke => writer.write_all(&[0, 0, 0, 1, MessageKind::Choke.to_u8()]),
        Message::Unchoke => writer.write_all(&[0, 0, 0, 1, MessageKind::Unchoke.to_u8()]),
        Message::Interested => writer.write_all(&[0, 0, 0, 1, MessageKind::Interested.to_u8()]),
        Message::NotInterested => {
            writer.write_all(&[0, 0, 0, 1, MessageKind::NotInterested.to_u8()])
        }
        Message::Have { index } => {
            write_u32(&mut writer, 4)?;
            write_u32(&mut writer, *index)?;
            Ok(())
        }
        Message::Bitfield { bitfield } => {
            todo!()
        }
        Message::Request {
            index,
            begin,
            length,
        } => {
            write_u32(&mut writer, 12)?;
            write_u32(&mut writer, *index)?;
            write_u32(&mut writer, *begin)?;
            write_u32(&mut writer, *length)?;
            Ok(())
        }
        Message::Piece { index, begin, data } => {
            let len = 8 + data.0.len() as u32;
            write_u32(&mut writer, len)?;
            write_u32(&mut writer, *index)?;
            write_u32(&mut writer, *begin)?;
            writer.write_all(&data.0)?;
            Ok(())
        }
        Message::Cancel {
            index,
            begin,
            length,
        } => {
            write_u32(&mut writer, 12)?;
            write_u32(&mut writer, *index)?;
            write_u32(&mut writer, *begin)?;
            write_u32(&mut writer, *length)?;
            Ok(())
        }
    }
}

slotmap::new_key_type! {
    pub struct PieceId;
    pub struct FileId;
}

#[derive(Debug, Clone)]
struct FileRange {
    id: FileId,
    offset: u64,
    length: u64,
}

#[derive(Debug, Clone)]
struct PieceDesc {
    id: PieceId,
    index: u32,
    hash: Sha1,
    length: u64,
    ranges: Vec<FileRange>,
}

#[derive(Debug, Clone)]
struct FileDesc {
    id: FileId,
    path: String,
    length: u64,
}

struct TorrentDesc {
    meta: Metainfo,
    pieces: SlotMap<PieceId, PieceDesc>,
    files: SlotMap<FileId, FileDesc>,
}

impl TorrentDesc {
    fn new(metainfo: Metainfo) -> Self {
        let mut pieces = SlotMap::<PieceId, PieceDesc>::default();
        let mut files = SlotMap::<FileId, FileDesc>::default();
        for file in &metainfo.info.files {
            files.insert_with_key(|id| FileDesc {
                id,
                path: file.path.clone(),
                length: file.length,
            });
        }

        let mut offset = 0;
        let mut remain = metainfo.info.length;
        for (piece_idx, piece_hash) in metainfo.info.pieces.iter().enumerate() {
            let length = remain.min(metainfo.info.piece_length);
            remain = remain.saturating_sub(length);

            let mut ranges = Vec::new();
            for file in files.values() {
                ranges.push(FileRange {
                    id: file.id,
                    offset,
                    length,
                });
            }

            pieces.insert_with_key(move |id| PieceDesc {
                id,
                index: piece_idx as u32,
                hash: *piece_hash,
                length,
                ranges,
            });

            offset += length;
        }

        Self {
            meta: metainfo,
            pieces,
            files,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read("bunny.torrent").unwrap();
    let metainfo = bencode::decode::<Metainfo>(&content).unwrap();
    let mut stream = TcpStream::connect("127.0.0.1:51413").unwrap();
    write_handshake(
        &mut stream,
        &Handshake {
            info_hash: metainfo.info_hash,
            peer_id: Default::default(),
        },
    )
    .unwrap();
    let handshake = read_handshake(&mut stream).unwrap();
    println!("{:#?}", handshake);

    let bitfield = match read_message(&mut stream).unwrap() {
        Message::Bitfield { bitfield } => bitfield,
        _ => panic!("expected first message to be bitfield"),
    };

    loop {
        for idx in 0..metainfo.info.pieces.len() {
            let piece_idx = idx as u32;
            let request_message = Message::Request {
                index: piece_idx,
                begin: 0,
                length: 0,
            };
        }
    }
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

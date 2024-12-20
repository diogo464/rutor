use std::{
    collections::VecDeque,
    io::{BufReader, BufWriter, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

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

type ArcMetaInfo = Arc<Metainfo>;

#[derive(Debug, Clone)]
pub struct Metainfo {
    pub announce: String,
    pub announce_list: Vec<Vec<String>>,
    pub info: Info,
    pub info_hash: Sha1,
}

#[derive(Debug, Clone)]
pub struct InfoFile {
    pub path: String,
    pub length: u64,
}

#[derive(Debug, Clone)]
pub struct Info {
    pub name: String,
    pub piece_length: u64,
    pub length: u64,
    pub pieces: Vec<Sha1>,
    pub files: Vec<InfoFile>,
}

impl Info {
    pub fn piece_length(&self, index: u32) -> u32 {
        let mut l = self.length;
        l = l.saturating_sub(u64::from(index) * self.piece_length);
        l.min(self.piece_length) as u32
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
pub struct Bitfield {
    data: Vec<u8>,
    bits: usize,
}

impl std::fmt::Debug for Bitfield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bitfield").field(&self.bits).finish()
    }
}

impl Bitfield {
    fn new(mut data: Vec<u8>, bits: usize) -> Self {
        let vec_len = (bits + 7) / 8;
        data.resize(vec_len, 0);
        Self { data, bits }
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
        bitfield: Vec<u8>,
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
            bitfield: buf[1..].to_owned(),
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
            write_u32(&mut writer, *index)?;
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
    pub struct PieceKey;
    pub struct FileKey;
    pub struct ChunkKey;
    pub struct PeerKey;
}

impl PieceKey {
    pub fn from_index(index: u32) -> PieceKey {
        PieceKey::from(slotmap::KeyData::from_ffi(u64::from(index)))
    }

    pub fn to_index(&self) -> u32 {
        (self.data().as_ffi() & 0xFFFFFFFF) as u32
    }
}

#[derive(Debug, Clone)]
struct FileRange {
    key: FileKey,
    offset: u64,
    length: u32,
}

#[derive(Debug, Clone)]
struct PieceDesc {
    key: PieceKey,
    index: u32,
    hash: Sha1,
    length: u32,
    ranges: Vec<FileRange>,
}

#[derive(Debug, Clone)]
struct FileDesc {
    key: FileKey,
    path: String,
    length: u64,
}

struct PieceIdxMap {
    ids: Vec<PieceKey>,
}

impl PieceIdxMap {
    fn new(ids: Vec<PieceKey>) -> Self {
        Self { ids }
    }

    fn get(&self, piece_idx: u32) -> Option<PieceKey> {
        self.ids.get(piece_idx as usize).copied()
    }
}

struct TorrentDesc {
    meta: Metainfo,
    pieces: SlotMap<PieceKey, PieceDesc>,
    pieces_map: PieceIdxMap,
    files: SlotMap<FileKey, FileDesc>,
}

impl TorrentDesc {
    fn new(metainfo: Metainfo) -> Self {
        let mut pieces = SlotMap::<PieceKey, PieceDesc>::default();
        let mut files = SlotMap::<FileKey, FileDesc>::default();
        for file in &metainfo.info.files {
            files.insert_with_key(|id| FileDesc {
                key: id,
                path: file.path.clone(),
                length: file.length,
            });
        }

        let mut offset = 0;
        let mut remain = metainfo.info.length;
        let mut piece_ids = Vec::with_capacity(metainfo.info.pieces.len());
        for (piece_idx, piece_hash) in metainfo.info.pieces.iter().enumerate() {
            let length = remain.min(metainfo.info.piece_length);
            remain = remain.saturating_sub(length);
            let length = length as u32;

            let mut ranges = Vec::new();
            for file in files.values() {
                ranges.push(FileRange {
                    key: file.key,
                    offset,
                    length,
                });
            }

            let piece_id = pieces.insert_with_key(move |id| PieceDesc {
                key: id,
                index: piece_idx as u32,
                hash: *piece_hash,
                length,
                ranges,
            });
            piece_ids.push(piece_id);

            offset += u64::from(length);
        }

        Self {
            meta: metainfo,
            pieces,
            pieces_map: PieceIdxMap::new(piece_ids),
            files,
        }
    }
}

const CHUNK_LENGTH: u32 = 16 * 1024;

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
    ) -> std::io::Result<(TcpStream, Handshake)> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_write_timeout(Some(Duration::from_secs(8)))?;
        write_handshake(&mut stream, &Handshake { info_hash, peer_id })?;
        let handshake = read_handshake(&mut stream)?;
        Ok((stream, handshake))
    }

    let (stream, handshake) = match try_connect(addr, peer_id, info_hash) {
        Ok((stream, handshake)) => (stream, handshake),
        Err(error) => {
            let _ = sender.send(TorrentMsg::PeerError { key, error });
            return;
        }
    };

    let send_result = sender.send(TorrentMsg::PeerHandshake {
        key,
        id: handshake.peer_id,
        info_hash: handshake.info_hash,
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

#[derive(Debug)]
enum TorrentMsg {
    PeerHandshake {
        key: PeerKey,
        id: PeerId,
        info_hash: Sha1,
    },
    PeerMessage {
        key: PeerKey,
        message: Message,
    },
    PeerError {
        key: PeerKey,
        error: std::io::Error,
    },
    ConnectToPeer {
        addr: SocketAddr,
    },
}

#[derive(Debug)]
struct FileState {
    path: PathBuf,
    length: u64,
}

#[derive(Debug)]
struct PieceState {
    hash: Sha1,
    length: u32,
    chunks: Vec<ChunkKey>,
    ranges: Vec<FileRange>,
}

#[derive(Debug)]
struct ChunkState {
    piece: PieceKey,
    /// offset relative to piece
    offset: u32,
    length: u32,
    assigned_peer: Option<PeerKey>,
}

#[derive(Debug)]
struct PeerState {
    id: PeerId,
    io: PeerIO,
    addr: SocketAddr,
    /// have we received the bitfield from the remote peer?
    /// if the first message is not the bitfield, then it is implied that it is empty
    bitfield_received: bool,
    bitfield: Bitfield,
    /// are we chocked by the peer
    local_choke: bool,
    /// are we choking the peer
    remote_choke: bool,
    /// is the peer interested in us
    local_interested: bool,
    /// are we interested in the peer
    remote_interested: bool,
    pending_chunks: Vec<ChunkKey>,
}

#[derive(Debug)]
struct TorrentState {
    info: ArcMetaInfo,
    queue: VecDeque<TorrentMsg>,
    files: SlotMap<FileKey, FileState>,
    pieces: SecondaryMap<PieceKey, PieceState>,
    chunks: SlotMap<ChunkKey, ChunkState>,
    peers: SlotMap<PeerKey, PeerState>,
}

impl TorrentState {
    pub fn from_metainfo(info: Metainfo) -> Self {
        let mut pieces = SecondaryMap::<PieceKey, PieceState>::default();
        let mut chunks = SlotMap::<ChunkKey, ChunkState>::default();
        let mut files = SlotMap::<FileKey, FileState>::default();
        let mut file_keys = Vec::default();

        for file in info.info.files.iter() {
            let path = PathBuf::from(file.path.clone());
            let file_key = files.insert(FileState {
                path,
                length: file.length,
            });
            file_keys.push(file_key);
        }

        for (index, &hash) in info.info.pieces.iter().enumerate() {
            let index = index as u32;
            let piece_key = PieceKey::from_index(index);
            let piece_length = info.info.piece_length(index);
            let num_chunks = (piece_length + CHUNK_LENGTH - 1) / CHUNK_LENGTH;
            pieces.insert(
                piece_key,
                PieceState {
                    hash,
                    length: piece_length,
                    chunks: Default::default(),
                    ranges: Default::default(),
                },
            );
            assert_eq!(piece_key.to_index(), index);

            let piece_ranges = {
                let piece_offset = u64::from(index) * info.info.piece_length;
                let mut ranges = Vec::default();
                let mut current_offset = 0;
                for &file_key in file_keys.iter() {
                    let file = &files[file_key];
                    let file_begin = current_offset;
                    let file_end = file_begin + file.length;

                    if piece_offset >= file_begin && piece_offset < file_end {
                        let file_offset = piece_offset - file_begin;
                        let range_length = (file.length - file_offset).min(u64::from(piece_length));

                        ranges.push(FileRange {
                            key: file_key,
                            offset: file_offset,
                            length: range_length as u32,
                        });
                    }

                    current_offset += file.length;
                }

                ranges
            };

            let piece_chunks = {
                let mut piece_chunks = Vec::with_capacity(num_chunks as usize);
                let mut rem_piece_length = piece_length;
                for i in 0..num_chunks {
                    let chunk_key = chunks.insert(ChunkState {
                        piece: piece_key,
                        offset: CHUNK_LENGTH * i,
                        length: rem_piece_length.min(CHUNK_LENGTH),
                        assigned_peer: Default::default(),
                    });
                    rem_piece_length = rem_piece_length.saturating_sub(CHUNK_LENGTH);
                    piece_chunks.push(chunk_key);
                }
                piece_chunks
            };

            pieces[piece_key].chunks = piece_chunks;
            pieces[piece_key].ranges = piece_ranges;
        }

        Self {
            info: Arc::new(info),
            queue: Default::default(),
            files,
            pieces,
            chunks,
            peers: Default::default(),
        }
    }

    pub fn queue_message(&mut self, message: TorrentMsg) {
        self.queue.push_back(message);
    }

    pub fn process_messages(&mut self) {
        while let Some(message) = self.queue.pop_front() {
            self.process_message(message);
        }
    }

    pub fn process_message(&mut self, message: TorrentMsg) {
        match message {
            TorrentMsg::PeerHandshake { key, id, info_hash } => todo!(),
            TorrentMsg::PeerMessage { key, message } => todo!(),
            TorrentMsg::PeerError { key, error } => todo!(),
            TorrentMsg::ConnectToPeer { addr } => {
                println!("received request to connect to peer at {addr}");
            }
        }
    }
}

#[derive(Clone)]
struct Torrent {
    sender: TorrentSender,
}

impl Torrent {
    pub fn new(metainfo: Metainfo) -> Self {
        let state = TorrentState::from_metainfo(metainfo);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || torrent_entry(state, receiver));
        Self { sender }
    }

    pub fn connect_to_peer(&self, addr: SocketAddr) {
        self.send(TorrentMsg::ConnectToPeer { addr });
    }

    fn send(&self, message: TorrentMsg) {
        self.sender
            .send(message)
            .expect("torrent loop should never exit while sender is alive")
    }
}

fn torrent_entry(mut state: TorrentState, receiver: TorrentReceiver) {
    while let Ok(msg) = receiver.recv() {
        state.queue_message(msg);
        state.process_messages();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read("bunny.torrent").unwrap();
    let metainfo = bencode::decode::<Metainfo>(&content).unwrap();
    let torrent = Torrent::new(metainfo);
    torrent.connect_to_peer("10.0.3.3:6881".parse()?);
    std::thread::sleep(Duration::from_secs(10));
    Ok(())
    // let torrent_state = TorrentState::from_metainfo(metainfo.clone());
    // println!("{torrent_state:#?}");
    //
    // let peer_id = PeerId::default();
    // //let mut stream = TcpStream::connect("127.0.0.1:51413").unwrap();
    // let mut stream = TcpStream::connect("10.0.3.3:6881").unwrap();
    // write_handshake(
    //     &mut stream,
    //     &Handshake {
    //         info_hash: metainfo.info_hash,
    //         peer_id: Default::default(),
    //     },
    // )
    // .unwrap();
    // let handshake = read_handshake(&mut stream).unwrap();
    // println!("{:#?}", handshake);
    //
    // // write_message(
    // //     &mut stream,
    // //     &Message::Bitfield {
    // //         bitfield: Default::default(),
    // //     },
    // // )?;
    //
    // let bitfield = match read_message(&mut stream).unwrap() {
    //     Message::Bitfield { bitfield } => Bitfield::new(bitfield, metainfo.info.pieces.len()),
    //     _ => panic!("expected first message to be bitfield"),
    // };
    // println!("{:#?}", bitfield);
    //
    // let mut chocked = true;
    // let mut state = TorrentDesc::new(metainfo.clone());
    // let mut next_piece_idx = 0;
    // let mut pending_piece = false;
    //
    // write_message(&mut stream, &Message::Interested)?;
    // write_message(&mut stream, &Message::Unchoke)?;
    //
    // loop {
    //     let message = read_message(&mut stream)?;
    //     println!("{message:#?}");
    //     match message {
    //         Message::Choke => chocked = true,
    //         Message::Unchoke => chocked = false,
    //         Message::Bitfield { .. } => panic!("received bitfield twice"),
    //         Message::Piece { index, begin, data } => println!("received piece"),
    //         _ => {}
    //     }
    //
    //     if !chocked && !pending_piece {
    //         let piece_idx = next_piece_idx;
    //         let piece_id = match state.pieces_map.get(piece_idx) {
    //             Some(id) => id,
    //             None => break,
    //         };
    //
    //         let piece_desc = &mut state.pieces[piece_id];
    //         let piece_len = piece_desc.length;
    //
    //         println!("sending piece request");
    //         write_message(
    //             &mut stream,
    //             &Message::Request {
    //                 index: piece_idx,
    //                 begin: 0,
    //                 length: 16 * 1024,
    //             },
    //         )?;
    //         pending_piece = true;
    //     }
    //
    //     // for idx in 0..metainfo.info.pieces.len() {
    //     //     let piece_idx = idx as u32;
    //     //     let request_message = Message::Request {
    //     //         index: piece_idx,
    //     //         begin: 0,
    //     //         length: 0,
    //     //     };
    //     // }
    // }
    //
    // Ok(())
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

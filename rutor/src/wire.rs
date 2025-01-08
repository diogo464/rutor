use std::io::{Read, Write};

use bytes::Bytes;

use crate::{PeerId, PieceIdx, Sha1};

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

#[derive(Debug)]
pub enum Message {
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
pub struct Handshake {
    pub info_hash: Sha1,
    pub peer_id: PeerId,
}

struct HandshakeSplit<'a> {
    prefix: &'a [u8; HANDSHAKE_PREFIX_LENGTH],
    reserved: &'a [u8; HANDSHAKE_RESERVED_LENGTH],
    info_hash: &'a [u8; 20],
    peer_id: &'a [u8; 20],
}

impl<'a> HandshakeSplit<'a> {
    fn new(buf: &'a [u8; HANDSHAKE_LENGTH]) -> HandshakeSplit<'a> {
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

pub fn serialize_handshake(handshake: &Handshake) -> [u8; HANDSHAKE_LENGTH] {
    let mut buf = [0u8; HANDSHAKE_LENGTH];
    buf[0..HANDSHAKE_PREFIX_LENGTH].copy_from_slice(HANDSHAKE_PREFIX);
    buf[HANDSHAKE_INFOHASH_IDX..HANDSHAKE_INFOHASH_IDX + 20]
        .copy_from_slice(handshake.info_hash.as_bytes());
    buf[HANDSHAKE_PEERID_IDX..HANDSHAKE_PEERID_IDX + 20]
        .copy_from_slice(handshake.info_hash.as_bytes());
    buf
}

pub fn write_handshake<W: Write>(mut writer: W, handshake: &Handshake) -> std::io::Result<()> {
    let buf = serialize_handshake(handshake);
    writer.write_all(&buf)?;
    Ok(())
}

pub fn read_handshake<R: Read>(mut reader: R) -> std::io::Result<Handshake> {
    let mut buf = [0u8; HANDSHAKE_LENGTH];
    reader.read_exact(&mut buf)?;

    let split = HandshakeSplit::new(&buf);
    assert_eq!(split.prefix, HANDSHAKE_PREFIX);

    Ok(Handshake {
        info_hash: Sha1(*split.info_hash),
        peer_id: PeerId(*split.peer_id),
    })
}

pub fn decode_message(buf: &[u8]) -> std::io::Result<Message> {
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

pub fn read_message<R: Read>(mut reader: R) -> std::io::Result<Message> {
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

pub fn write_message<W: Write>(mut writer: W, message: &Message) -> std::io::Result<()> {
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
            let len = 9 + data.len() as u32;
            write_u32(&mut writer, len)?;
            write_message_kind(&mut writer, MessageKind::Piece)?;
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

use std::{
    io::{Cursor, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::Duration,
};

use serde::Serialize;

use crate::{PeerId, Sha1};

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
pub struct AnnounceParams {
    pub info_hash: Sha1,
    pub peer_id: PeerId,
    pub downloaded: u64,
    pub left: u64,
    pub uploaded: u64,
    pub event: Event,
    pub ip_address: Option<Ipv4Addr>,
    pub num_want: Option<u32>,
    pub port: u16,
}

#[derive(Debug)]
pub struct Announce {
    pub interval: u32,
    pub leechers: u32,
    pub seeders: u32,
    pub addresses: Vec<SocketAddrV4>,
}

pub struct TrackerUdpClient {
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
        //println!("connection id = {connection_id}");
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

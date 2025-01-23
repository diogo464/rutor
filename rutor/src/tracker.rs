use std::net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs as _};

pub mod http;
pub mod udp;

use crate::{PeerId, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Connect = 0,
    Announce = 1,
    Scrape = 2,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    #[default]
    None = 0,
    Completed = 1,
    Started = 2,
    Stopped = 3,
}

#[derive(Debug, Default, Clone)]
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

#[derive(Debug)]
pub enum TrackerClient {
    Http(http::TrackerHttpClient),
    Udp(udp::TrackerUdpClient),
}

impl TrackerClient {
    pub async fn new(url: &str) -> std::io::Result<Self> {
        if let Some(url) = url.strip_prefix("udp://") {
            let addrs = tokio::task::block_in_place(|| {
                url.to_socket_addrs()
                    .map(|v| v.into_iter().collect::<Vec<_>>())
            })?;
            let addr = match addrs.first().copied() {
                Some(addr) => addr,
                None => return Err(std::io::Error::other("failed to resolve tracker url")),
            };
            Ok(Self::Udp(udp::TrackerUdpClient::new(addr).await?))
        } else if url.starts_with("http://") || url.starts_with("https://") {
            Ok(Self::Http(http::TrackerHttpClient::new(url.to_string())?))
        } else {
            Err(std::io::Error::other("unsupported tracker protocol"))
        }
    }

    pub async fn announce(&mut self, params: &AnnounceParams) -> std::io::Result<Announce> {
        match self {
            Self::Http(client) => client.announce(params).await,
            Self::Udp(client) => client.announce(params).await,
        }
    }
}

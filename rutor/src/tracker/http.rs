use std::net::SocketAddrV4;

use serde::Serialize;

use super::{Announce, AnnounceParams, Event};

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

#[derive(Debug)]
pub struct TrackerHttpClient {
    addr: String,
    client: reqwest::Client,
}

impl TrackerHttpClient {
    pub fn new(addr: String) -> std::io::Result<Self> {
        Ok(Self {
            addr,
            client: reqwest::Client::new(),
        })
    }

    pub async fn announce(&mut self, params: &AnnounceParams) -> std::io::Result<Announce> {
        let response_data = self
            .client
            .get(&self.addr)
            .query(&("info_hash", params.info_hash.as_bytes()))
            .query(&("peer_id", params.peer_id.as_bytes()))
            .query(&("port", params.port))
            .query(&("uploaded", params.uploaded))
            .query(&("downloaded", params.downloaded))
            .query(&("left", params.left))
            .query(&("compact", 1))
            .query(&(
                "event",
                match params.event {
                    Event::Completed => "completed",
                    Event::Started => "started",
                    Event::Stopped => "stopped",
                    Event::None => "",
                },
            ))
            .query(&("numwant", params.num_want.unwrap_or(50)))
            .send()
            .await
            .map_err(std::io::Error::other)?
            .bytes()
            .await
            .map_err(std::io::Error::other)?;

        let response =
            bencode::decode::<TrackerResponse>(&response_data).map_err(std::io::Error::other)?;

        match response {
            TrackerResponse::Success {
                interval,
                complete,
                incomplete,
                peers,
                ..
            } => Ok(Announce {
                interval,
                leechers: incomplete,
                seeders: complete,
                addresses: peers,
            }),
            TrackerResponse::Failure { reason } => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("tracker failure: {}", reason),
            )),
        }
    }
}

enum TrackerResponse {
    Success {
        warning: Option<String>,
        interval: u32,
        complete: u32,
        incomplete: u32,
        peers: Vec<SocketAddrV4>,
    },
    Failure {
        reason: String,
    },
}

impl bencode::FromValue for TrackerResponse {
    fn from_value(value: &bencode::Value) -> bencode::Result<Self> {
        let dict = value.as_dict()?;

        if let Some(reason) = dict.find::<String>(b"failure reason")? {
            return Ok(TrackerResponse::Failure { reason });
        }

        Ok(TrackerResponse::Success {
            warning: dict.find::<String>(b"warning message")?,
            interval: dict.require::<u32>(b"interval")?,
            complete: dict.require::<u32>(b"complete")?,
            incomplete: dict.require::<u32>(b"incomplete")?,
            peers: dict
                .require::<Vec<u8>>(b"peers")?
                .chunks(6)
                .map(|chunk| {
                    let ip = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                    SocketAddrV4::new(ip.into(), port)
                })
                .collect(),
        })
    }
}

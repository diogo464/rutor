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
    pub fn new(addr: impl Into<String>) -> std::io::Result<Self> {
        Ok(Self {
            addr: addr.into(),
            client: reqwest::Client::new(),
        })
    }

    pub async fn announce(&mut self, params: &AnnounceParams) -> std::io::Result<Announce> {
        let request_url = format!(
            "{}?info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&compact=1{}&numwant={}",
            self.addr,
            percent_encode_bytes(params.info_hash.as_bytes()),
            percent_encode_bytes(params.peer_id.as_bytes()),
            params.port,
            params.uploaded,
            params.downloaded,
            params.left,
            match params.event {
                Event::Completed => "&event=completed",
                Event::Started => "&event=started",
                Event::Stopped => "&event=stopped",
                Event::None => "",
            },
            params.num_want.unwrap_or(50),
        );

        let response_data = self
            .client
            .get(request_url)
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
                .require_value(b"peers")?
                .as_bytes()?
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

fn percent_encode_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 3);
    for b in bytes {
        let upper = (*b >> 4) & 0xF;
        let lower = *b & 0xF;
        output.push('%');
        output.push(if upper < 10 {
            (b'0' + upper) as char
        } else {
            (b'A' + upper - 10) as char
        });
        output.push(if lower < 10 {
            (b'0' + lower) as char
        } else {
            (b'A' + lower - 10) as char
        });
    }
    output
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn percent_encode_bytes_test() {
        let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        assert_eq!(
            percent_encode_bytes(&data),
            "%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F"
        );
    }
}

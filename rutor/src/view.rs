use std::net::SocketAddr;

use crate::{PeerId, TorrentInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TorrentViewState {
    Paused,
    Running,
    Checking,
}

#[derive(Debug, Clone)]
pub struct TorrentViewPeer {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub upload_rate: u32,
    pub download_rate: u32,
}

#[derive(Debug, Clone)]
pub struct TorrentView {
    pub info: TorrentInfo,
    pub peers: Vec<TorrentViewPeer>,
    pub progress: f64,
    pub state: TorrentViewState,
}

impl TorrentView {
    pub fn complete(&self) -> bool {
        self.progress == 1.0
    }
}

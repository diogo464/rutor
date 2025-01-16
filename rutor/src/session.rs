use std::{net::SocketAddr, pin::Pin, time::Duration};

use bytes::Bytes;
use slotmap::{SecondaryMap, SlotMap};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{
        mpsc::{UnboundedReceiver, UnboundedSender},
        oneshot,
    },
    task::{AbortHandle, JoinHandle},
};

use crate::{wire, Announce, NetworkStats, PeerId, PieceIdx, Sha1, TorrentInfo, TorrentView};

mod listener;
use listener::ListenerProc;

mod peer;
use peer::PeerProc;

mod tracker;
use tracker::TrackerProc;

mod disk;
use disk::DiskProc;

mod torrent;
pub use torrent::TorrentConfig;
use torrent::{PeerKey, TorrentCmd, TorrentState, TrackerKey};

type Sender<T> = UnboundedSender<T>;
type Receiver<T> = UnboundedReceiver<T>;
type SessionSender = Sender<SessionMsg>;
type SessionReceiver = Receiver<SessionMsg>;

slotmap::new_key_type! {
    pub struct TorrentKey;
}

macro_rules! torrent_or_return {
    ($state:expr, $key:expr) => {
        match $state.torrents.get($key) {
            Some(torrent) => torrent,
            None => return,
        }
    };
    ($state:expr, mut $key:expr) => {
        match $state.torrents.get_mut($key) {
            Some(torrent) => torrent,
            None => return,
        }
    };
}

type PeerReader = Pin<Box<dyn AsyncRead + Send + 'static>>;
type PeerWriter = Pin<Box<dyn AsyncWrite + Send + 'static>>;

struct PeerIo {
    reader: PeerReader,
    writer: PeerWriter,
}

impl PeerIo {
    fn new(
        reader: impl AsyncRead + Send + 'static,
        writer: impl AsyncWrite + Send + 'static,
    ) -> Self {
        Self {
            reader: Box::pin(reader),
            writer: Box::pin(writer),
        }
    }
}

enum SessionMsg {
    ListenerIncoming {
        peer_id: PeerId,
        peer_addr: SocketAddr,
        info_hash: Sha1,
        peer_io: PeerIo,
    },
    PeerHandshake {
        torrent_key: TorrentKey,
        peer_key: PeerKey,
        peer_id: PeerId,
    },
    PeerMessage {
        torrent_key: TorrentKey,
        peer_key: PeerKey,
        message: wire::Message,
    },
    PeerFailure {
        torrent_key: TorrentKey,
        peer_key: PeerKey,
        error: std::io::Error,
    },
    TrackerAnnounce {
        torrent_key: TorrentKey,
        tracker_key: TrackerKey,
        announce: Announce,
    },
    TrackerError {
        torrent_key: TorrentKey,
        tracker_key: TrackerKey,
        error: std::io::Error,
    },
    PieceReadSuccess {
        torrent_key: TorrentKey,
        piece_idx: PieceIdx,
        piece_data: Bytes,
    },
    PieceReadError {
        torrent_key: TorrentKey,
        piece_idx: PieceIdx,
        error: std::io::Error,
    },
    PieceWriteError {
        torrent_key: TorrentKey,
        piece_idx: PieceIdx,
        error: std::io::Error,
    },
    TorrentTick,
    TorrentAdd {
        info: TorrentInfo,
        config: TorrentConfig,
        response: oneshot::Sender<Torrent>,
    },
    TorrentConnect {
        torrent_key: TorrentKey,
        address: SocketAddr,
    },
    TorrentView {
        torrent_key: TorrentKey,
        response: oneshot::Sender<TorrentView>,
    },
    Shutdown,
}

impl SessionMsg {
    fn torrent_key(&self) -> Option<TorrentKey> {
        match self {
            SessionMsg::ListenerIncoming {
                peer_id: _,
                peer_addr: _,
                info_hash: _,
                peer_io: _,
            } => None,
            SessionMsg::PeerHandshake { torrent_key, .. } => Some(*torrent_key),
            SessionMsg::PeerMessage { torrent_key, .. } => Some(*torrent_key),
            SessionMsg::PeerFailure { torrent_key, .. } => Some(*torrent_key),
            SessionMsg::TrackerAnnounce { torrent_key, .. } => Some(*torrent_key),
            SessionMsg::TrackerError { torrent_key, .. } => Some(*torrent_key),
            SessionMsg::PieceReadSuccess { torrent_key, .. } => Some(*torrent_key),
            SessionMsg::PieceReadError { torrent_key, .. } => Some(*torrent_key),
            SessionMsg::PieceWriteError { torrent_key, .. } => Some(*torrent_key),
            SessionMsg::TorrentTick => None,
            SessionMsg::TorrentAdd {
                info: _,
                config: _,
                response: _,
            } => None,
            SessionMsg::TorrentConnect {
                torrent_key,
                address: _,
            } => Some(*torrent_key),
            SessionMsg::TorrentView { torrent_key, .. } => Some(*torrent_key),
            SessionMsg::Shutdown => None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct SessionConfig {
    pub listen_addr: Option<SocketAddr>,
}

pub struct Session {
    sender: SessionSender,
    tick_handle: AbortHandle,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.tick_handle.abort();
        self.send(SessionMsg::Shutdown);
    }
}

impl Session {
    pub fn new() -> Self {
        Self::new_with(Default::default())
    }

    pub fn new_with(config: SessionConfig) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let listener = match config.listen_addr {
            Some(addr) => Some(ListenerProc::spawn(sender.clone(), addr)),
            None => None,
        };
        let state = SessionState::new(config, sender.clone(), listener);
        tokio::task::spawn_blocking(move || session_run(state, receiver));
        let tick_handle = tokio::task::spawn({
            let sender = sender.clone();
            async move {
                while sender.send(SessionMsg::TorrentTick).is_ok() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        })
        .abort_handle();
        Self {
            sender,
            tick_handle,
        }
    }

    pub async fn torrent_add(&self, info: TorrentInfo) -> Torrent {
        self.torrent_add_with(info, Default::default()).await
    }

    pub async fn torrent_add_with(&self, info: TorrentInfo, config: TorrentConfig) -> Torrent {
        let (sender, receiver) = oneshot::channel();
        self.send(SessionMsg::TorrentAdd {
            info,
            config,
            response: sender,
        });
        receiver.await.unwrap()
    }

    fn send(&self, message: SessionMsg) {
        self.sender
            .send(message)
            .expect("session should not exist while sender exists")
    }
}

struct SessionTorrentEntry {
    state: TorrentState,
    disk: DiskProc,
    trackers: SecondaryMap<TrackerKey, TrackerProc>,
    peers: SecondaryMap<PeerKey, PeerProc>,
}

struct SessionState {
    config: SessionConfig,
    sender: SessionSender,
    listener: Option<ListenerProc>,
    torrents: SlotMap<TorrentKey, SessionTorrentEntry>,
}

impl SessionState {
    fn new(config: SessionConfig, sender: SessionSender, listener: Option<ListenerProc>) -> Self {
        Self {
            config,
            sender,
            listener,
            torrents: Default::default(),
        }
    }
}

fn session_run(mut state: SessionState, mut receiver: SessionReceiver) {
    while let Some(msg) = receiver.blocking_recv() {
        let shutdown = session_process(&mut state, msg);
        if shutdown {
            break;
        }
    }
}

fn session_process(state: &mut SessionState, msg: SessionMsg) -> bool {
    let torrent_key = msg.torrent_key();

    match msg {
        SessionMsg::ListenerIncoming {
            peer_id,
            peer_addr,
            info_hash,
            peer_io,
        } => session_process_listener_incoming(state, peer_id, peer_addr, info_hash, peer_io),
        SessionMsg::PeerHandshake {
            torrent_key,
            peer_key,
            peer_id,
        } => session_process_peer_handshake(state, torrent_key, peer_key, peer_id),
        SessionMsg::PeerMessage {
            torrent_key,
            peer_key,
            message,
        } => session_process_peer_message(state, torrent_key, peer_key, message),
        SessionMsg::PeerFailure {
            torrent_key,
            peer_key,
            error,
        } => session_process_peer_failure(state, torrent_key, peer_key, error),
        SessionMsg::TrackerAnnounce {
            torrent_key,
            tracker_key,
            announce,
        } => session_process_tracker_announce(state, torrent_key, tracker_key, announce),
        SessionMsg::TrackerError {
            torrent_key,
            tracker_key,
            error,
        } => session_process_tracker_error(state, torrent_key, tracker_key, error),
        SessionMsg::PieceReadSuccess {
            torrent_key,
            piece_idx,
            piece_data,
        } => session_process_piece_read_success(state, torrent_key, piece_idx, piece_data),
        SessionMsg::PieceReadError {
            torrent_key,
            piece_idx,
            error,
        } => session_process_piece_read_error(state, torrent_key, piece_idx, error),
        SessionMsg::PieceWriteError {
            torrent_key,
            piece_idx,
            error,
        } => session_process_piece_write_error(state, torrent_key, piece_idx, error),
        SessionMsg::TorrentTick => session_process_torrent_tick(state),
        SessionMsg::TorrentAdd {
            info,
            config,
            response,
        } => session_process_torrent_add(state, info, config, response),
        SessionMsg::TorrentConnect {
            torrent_key,
            address,
        } => {
            session_process_torrent_connect(state, torrent_key, address);
        }
        SessionMsg::TorrentView {
            torrent_key,
            response,
        } => session_process_torrent_view(state, torrent_key, response),
        SessionMsg::Shutdown => return true,
    }

    if let Some(torrent_key) = torrent_key {
        session_torrent_drain_and_execute(state, torrent_key);
    }

    false
}

fn session_process_listener_incoming(
    state: &mut SessionState,
    peer_id: PeerId,
    peer_addr: SocketAddr,
    info_hash: Sha1,
    peer_io: PeerIo,
) {
    for (torrent_key, torrent) in state.torrents.iter_mut() {
        if torrent.state.info_hash() == info_hash {
            let peer_key = torrent.state.on_peer_connect(peer_id, peer_addr);
            let peer_proc = PeerProc::accept(
                state.sender.clone(),
                torrent_key,
                peer_key,
                info_hash,
                torrent.state.id(),
                peer_io,
            );
            torrent.peers.insert(peer_key, peer_proc);
            break;
        }
    }
}

fn session_process_peer_handshake(
    state: &mut SessionState,
    torrent_key: TorrentKey,
    peer_key: PeerKey,
    peer_id: PeerId,
) {
    let torrent = torrent_or_return!(state, mut torrent_key);
    torrent.state.on_peer_handshake(peer_key, peer_id);
}

fn session_process_peer_message(
    state: &mut SessionState,
    torrent_key: TorrentKey,
    peer_key: PeerKey,
    message: wire::Message,
) {
    let torrent = torrent_or_return!(state, mut torrent_key);
    torrent.state.on_peer_message(peer_key, message);
}

fn session_process_peer_failure(
    state: &mut SessionState,
    torrent_key: TorrentKey,
    peer_key: PeerKey,
    error: std::io::Error,
) {
    let torrent = torrent_or_return!(state, mut torrent_key);
    torrent.state.on_peer_failure(peer_key, error);
}

fn session_process_tracker_announce(
    state: &mut SessionState,
    torrent_key: TorrentKey,
    tracker_key: TrackerKey,
    announce: Announce,
) {
    let torrent = torrent_or_return!(state, mut torrent_key);
    torrent.state.on_tracker_announce(tracker_key, announce);
}

fn session_process_tracker_error(
    state: &mut SessionState,
    torrent_key: TorrentKey,
    tracker_key: TrackerKey,
    error: std::io::Error,
) {
    let torrent = torrent_or_return!(state, mut torrent_key);
    torrent.state.on_tracker_error(tracker_key, error);
}

fn session_process_piece_read_success(
    state: &mut SessionState,
    torrent_key: TorrentKey,
    piece_idx: PieceIdx,
    piece_data: Bytes,
) {
    let torrent = torrent_or_return!(state, mut torrent_key);
    torrent.state.on_piece_read_success(piece_idx, piece_data);
}

fn session_process_piece_read_error(
    state: &mut SessionState,
    torrent_key: TorrentKey,
    piece_idx: PieceIdx,
    error: std::io::Error,
) {
    let torrent = torrent_or_return!(state, mut torrent_key);
    torrent.state.on_piece_read_error(piece_idx, error);
}

fn session_process_piece_write_error(
    state: &mut SessionState,
    torrent_key: TorrentKey,
    piece_idx: PieceIdx,
    error: std::io::Error,
) {
    let torrent = torrent_or_return!(state, mut torrent_key);
    torrent.state.on_piece_write_error(piece_idx, error);
}

fn session_process_torrent_tick(state: &mut SessionState) {
    let keys = state.torrents.keys().collect::<Vec<_>>();
    for key in keys {
        let torrent = &mut state.torrents[key];
        torrent.state.tick();
        session_torrent_drain_and_execute(state, key);
    }
}

fn session_process_torrent_add(
    state: &mut SessionState,
    info: TorrentInfo,
    config: TorrentConfig,
    response: oneshot::Sender<Torrent>,
) {
    // TODO: check torrent with info hash already exists
    let key = state.torrents.insert_with_key(|key| SessionTorrentEntry {
        state: TorrentState::new(info.clone(), config),
        disk: DiskProc::spawn(state.sender.clone(), key, info.clone(), Default::default()),
        trackers: Default::default(),
        peers: Default::default(),
    });

    let _ = response.send(Torrent {
        sender: state.sender.clone(),
        key,
    });

    state.torrents[key].state.init();
    session_torrent_drain_and_execute(state, key);
}

fn session_process_torrent_connect(
    state: &mut SessionState,
    torrent_key: TorrentKey,
    address: SocketAddr,
) {
    let torrent = torrent_or_return!(state, mut torrent_key);
    torrent.state.connect(address);
}

fn session_process_torrent_view(
    state: &mut SessionState,
    torrent_key: TorrentKey,
    response: oneshot::Sender<TorrentView>,
) {
    let torrent = torrent_or_return!(state, torrent_key);
    let view = torrent.state.view();
    let _ = response.send(view);
}

fn session_torrent_drain_and_execute(state: &mut SessionState, torrent_key: TorrentKey) {
    let torrent = torrent_or_return!(state, mut torrent_key);
    let mut exit = false;
    while !exit {
        exit = true;
        let commands = torrent.state.drain().collect::<Vec<_>>();
        for command in commands {
            exit = false;
            match command {
                TorrentCmd::PieceRead { piece_idx } => torrent.disk.read(piece_idx),
                TorrentCmd::PieceWrite {
                    piece_idx,
                    piece_data,
                } => torrent.disk.write(piece_idx, piece_data),
                TorrentCmd::PeerConnect { peer_key, address } => {
                    let peer = PeerProc::connect(
                        state.sender.clone(),
                        torrent_key,
                        peer_key,
                        torrent.state.info_hash(),
                        torrent.state.id(),
                        address,
                    );
                    torrent.peers.insert(peer_key, peer);
                }
                TorrentCmd::PeerDisconnect { peer_key } => {
                    torrent.peers.remove(peer_key);
                }
                TorrentCmd::PeerSend { peer_key, message } => {
                    let peer = &torrent.peers[peer_key];
                    peer.send(message);
                }
                TorrentCmd::TrackerConnect {
                    tracker_key,
                    tracker_url,
                } => {
                    let tracker = TrackerProc::spawn(
                        state.sender.clone(),
                        torrent_key,
                        tracker_key,
                        tracker_url,
                    );
                    torrent.trackers.insert(tracker_key, tracker);
                }
                TorrentCmd::TrackerAnnounce {
                    tracker_key,
                    params,
                } => {
                    let tracker = &torrent.trackers[tracker_key];
                    tracker.announce(&params);
                }
            }
        }
    }
}

///////// TORRENT ///////////////

#[derive(Clone)]
pub struct Torrent {
    sender: SessionSender,
    key: TorrentKey,
}

impl Torrent {
    pub async fn completed(&self) -> bool {
        let view = self.view().await;
        view.complete()
    }

    pub fn connect(&self, addr: SocketAddr) {
        self.send(SessionMsg::TorrentConnect {
            torrent_key: self.key,
            address: addr,
        });
    }

    pub async fn view(&self) -> TorrentView {
        let (sender, receiver) = oneshot::channel();
        self.send(SessionMsg::TorrentView {
            torrent_key: self.key,
            response: sender,
        });
        receiver.await.unwrap()
    }

    fn send(&self, message: SessionMsg) {
        self.sender
            .send(message)
            .expect("session should not exit while sender is alive")
    }
}

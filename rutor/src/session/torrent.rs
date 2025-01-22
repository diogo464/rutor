use std::{
    collections::VecDeque,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use slotmap::{Key as _, SecondaryMap, SlotMap};

use crate::{
    wire, Announce, AnnounceParams, Event, NetworkStatsAccum, PeerId, PieceBitfield, PieceIdx,
    Sha1, TorrentInfo, TorrentView, TorrentViewPeer, TorrentViewState,
};

const CHUNK_LENGTH: u32 = 16 * 1024;
const MAX_PEER_PENDING_CHUNKS: usize = 32;
const PEER_COUNT_LIMIT: usize = 50;

slotmap::new_key_type! {
    pub struct PeerKey;
    pub struct TrackerKey;
    struct PieceKey;
    struct FileKey;
    struct ChunkKey;
}

impl PieceKey {
    pub fn from_index(index: PieceIdx) -> PieceKey {
        PieceKey::from(slotmap::KeyData::from_ffi(u64::from(u32::from(index))))
    }

    pub fn to_index(&self) -> PieceIdx {
        PieceIdx::from((self.data().as_ffi() & 0xFFFFFFFF) as u32)
    }
}

#[derive(Debug)]
pub struct TorrentConfig {
    pub use_trackers: bool,
    pub assume_complete: bool,
}

impl Default for TorrentConfig {
    fn default() -> Self {
        Self {
            use_trackers: true,
            assume_complete: false,
        }
    }
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
    key: PeerKey,
    addr: SocketAddr,
    network_stats: NetworkStatsAccum,
    // TODO: have a timeout to disconnect peers that don't send a handshake in a couple of seconds
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
    /// Create a new incoming peer state
    /// We already know the peer id and address since we read the handshake
    pub fn new_incoming(key: PeerKey, id: PeerId, addr: SocketAddr) -> Self {
        Self {
            id,
            key,
            addr,
            network_stats: Default::default(),
            handshake_received: true,
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

    pub fn new_outgoing(key: PeerKey, addr: SocketAddr) -> Self {
        Self {
            id: Default::default(),
            key,
            addr,
            network_stats: Default::default(),
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
    key: TrackerKey,
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

#[derive(Debug, Clone)]
pub enum TorrentCmd {
    PieceRead {
        piece_idx: PieceIdx,
    },
    PieceWrite {
        piece_idx: PieceIdx,
        piece_data: Bytes,
    },
    PeerConnect {
        peer_key: PeerKey,
        address: SocketAddr,
    },
    PeerDisconnect {
        peer_key: PeerKey,
    },
    PeerSend {
        peer_key: PeerKey,
        message: wire::Message,
    },
    TrackerConnect {
        tracker_key: TrackerKey,
        tracker_url: String,
    },
    TrackerAnnounce {
        tracker_key: TrackerKey,
        params: AnnounceParams,
    },
}

#[derive(Debug, Default, Clone)]
struct CommandQueue(VecDeque<TorrentCmd>);

impl CommandQueue {
    fn read(&mut self, piece_idx: PieceIdx) {
        self.push(TorrentCmd::PieceRead { piece_idx });
    }

    fn write(&mut self, piece_idx: PieceIdx, piece_data: Bytes) {
        self.push(TorrentCmd::PieceWrite {
            piece_idx,
            piece_data,
        });
    }

    fn connect(&mut self, peer_key: PeerKey, address: SocketAddr) {
        self.push(TorrentCmd::PeerConnect { peer_key, address });
    }

    fn disconnect(&mut self, peer_key: PeerKey) {
        self.push(TorrentCmd::PeerDisconnect { peer_key });
    }

    fn send(&mut self, peer_key: PeerKey, message: wire::Message) {
        self.push(TorrentCmd::PeerSend { peer_key, message });
    }

    fn announce(&mut self, tracker_key: TrackerKey, params: AnnounceParams) {
        self.push(TorrentCmd::TrackerAnnounce {
            tracker_key,
            params,
        });
    }

    fn tracker_connect(&mut self, tracker_key: TrackerKey, tracker_url: String) {
        self.push(TorrentCmd::TrackerConnect {
            tracker_key,
            tracker_url,
        });
    }

    fn push(&mut self, command: TorrentCmd) {
        self.0.push_back(command);
    }
}

#[derive(Debug)]
pub struct TorrentState {
    id: PeerId,
    mode: TorrentMode,
    config: TorrentConfig,
    info: TorrentInfo,
    queue: CommandQueue,
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
                let path = parent_path.join(PathBuf::from(file.path()));
                let file_key = files.insert(FileState {
                    path,
                    offset: current_offset,
                    length: file.length(),
                });
                file_keys.push(file_key);
                current_offset += file.length();
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

        let bitfield = PieceBitfield::with_size(info.pieces_count());
        let checking_bitfield = PieceBitfield::with_size(info.pieces_count());
        Self {
            id: Default::default(),
            mode: TorrentMode::Starting,
            config,
            info,
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

    pub fn id(&self) -> PeerId {
        self.id
    }

    pub fn info_hash(&self) -> Sha1 {
        self.info.info_hash()
    }

    pub fn drain(&mut self) -> impl Iterator<Item = TorrentCmd> + '_ {
        self.queue.0.drain(..)
    }

    pub fn init(&mut self) {
        self.trackers_add_default();
        self.check();
    }

    pub fn tick(&mut self) {
        if self.mode == TorrentMode::Running {
            self.check_peer_interests();
            self.request_chunks();

            if self.config.use_trackers {
                self.trackers_announce();
            }
        }
    }

    pub fn check(&mut self) {
        self.mode = TorrentMode::Checking;
        self.disconnect_peers();
        self.bitfield.clear();
        //println!("started checking torrent");

        if self.config.assume_complete {
            self.mode = TorrentMode::Running;
            self.bitfield.fill();
        } else {
            for piece_idx in self.info.piece_indices() {
                self.queue.read(piece_idx);
            }
        }
    }

    pub fn connect(&mut self, address: SocketAddr) {
        self.process_connect_to_peer(address);
    }

    pub fn view(&self) -> TorrentView {
        let mut peers = Vec::with_capacity(self.peers.len());
        for peer in self.peers.values() {
            peers.push(TorrentViewPeer {
                id: peer.id,
                addr: peer.addr,
                upload_rate: peer.network_stats.upload_rate(),
                download_rate: peer.network_stats.download_rate(),
            });
        }

        TorrentView {
            info: self.info.clone(),
            peers,
            progress: (self.bitfield.num_set() as f64) / (self.bitfield.len() as f64),
            state: match self.mode {
                TorrentMode::Starting => TorrentViewState::Running,
                TorrentMode::Checking => TorrentViewState::Checking,
                TorrentMode::Running => TorrentViewState::Running,
                TorrentMode::Paused => TorrentViewState::Paused,
                TorrentMode::Failed => TorrentViewState::Paused,
            },
        }
    }
}

impl TorrentState {
    pub fn on_peer_connect(&mut self, peer_id: PeerId, peer_addr: SocketAddr) -> PeerKey {
        let key = self
            .peers
            .insert_with_key(|key| PeerState::new_incoming(key, peer_id, peer_addr));
        self.queue.send(
            key,
            wire::Message::Bitfield {
                bitfield: self.bitfield.clone().into_vec(),
            },
        );
        key
    }

    pub fn on_peer_handshake(&mut self, peer_key: PeerKey, peer_id: PeerId) {
        let peer = match self.peers.get_mut(peer_key) {
            Some(peer) => peer,
            None => return,
        };

        if peer.handshake_received {
            self.disconnect_peer(peer_key);
            return;
        }

        tracing::info!("received handshake for peer id {peer_id:?}");
        peer.handshake_received = true;
        peer.id = peer_id;
    }

    pub fn on_peer_message(&mut self, peer_key: PeerKey, message: wire::Message) {
        let peer = match self.peers.get_mut(peer_key) {
            Some(peer) => peer,
            None => return,
        };

        if !peer.handshake_received {
            //println!("received peer message before handshake");
            self.disconnect_peer(peer_key);
            return;
        }

        if let wire::Message::Bitfield { bitfield } = message {
            //println!("received bitfield");
            if peer.bitfield_received {
                //println!("received duplicate peer bitfield");
                self.disconnect_peer(peer_key);
                return;
            }
            peer.bitfield_received = true;
            peer.bitfield = PieceBitfield::from_vec(bitfield, self.info.pieces_count());
        } else {
            if !peer.bitfield_received {
                //println!("received peer message before bitfield, assuming empty bitfield");
                peer.bitfield_received = true;
                peer.bitfield = PieceBitfield::with_size(self.info.pieces_count());
            }

            match message {
                wire::Message::Choke => {
                    //println!("peer choked");
                    peer.remote_choke = true;
                    self.peer_cancel_all_chunks(peer_key);
                }
                wire::Message::Unchoke => {
                    //println!("peer unchoked");
                    peer.remote_choke = false
                }
                wire::Message::Interested => {
                    //println!("peer interested");
                    peer.remote_interested = true;
                    if peer.local_choke {
                        peer.local_choke = false;
                        self.queue.send(peer.key, wire::Message::Unchoke);
                    }
                }
                wire::Message::NotInterested => {
                    //println!("peer not interested");
                    peer.remote_interested = false;
                    if !peer.local_choke {
                        peer.local_choke = true;
                        self.queue.send(peer.key, wire::Message::Choke);
                    }
                }
                wire::Message::Have { index } => self.process_peer_have(peer_key, index),
                wire::Message::Bitfield { .. } => unreachable!(),
                wire::Message::Request {
                    index,
                    begin,
                    length,
                } => self.process_peer_request(peer_key, index, begin, length),
                wire::Message::Piece { index, begin, data } => {
                    let piece_key = PieceKey::from_index(index);
                    if !self.pieces.contains_key(piece_key) {
                        //println!("peer sent Piece message with invalid piece index");
                        self.disconnect_peer(peer_key);
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
                            self.process_received_chunk(peer_key, chunk_key, data);
                        }
                        None => {
                            //println!("received unrequest piece from peer");
                            // NOTE: don't disconnect here since we might have sent a Cancel
                            // message that the peer did not receive before sending us the piece.
                            return;
                        }
                    }
                }
                wire::Message::Cancel {
                    index,
                    begin,
                    length,
                } => self.process_peer_cancel(peer_key, index, begin, length),
            }
        }
    }

    pub fn on_peer_failure(&mut self, peer_key: PeerKey, error: std::io::Error) {
        let addr = match self.peers.get(peer_key) {
            Some(peer) => peer.addr,
            None => return,
        };
        tracing::warn!(addr = ?addr, "peer failure: {error}");
        self.disconnect_peer(peer_key);
    }

    pub fn on_tracker_announce(&mut self, tracker_key: TrackerKey, announce: Announce) {
        let tracker = match self.trackers.get_mut(tracker_key) {
            Some(tracker) => tracker,
            None => return,
        };

        tracker.next_announce = Instant::now() + Duration::from_secs(u64::from(announce.interval));
        tracker.status = format!("ok");

        self.process_tracker_address_list(announce.addresses.into_iter().map(From::from).collect());
    }

    pub fn on_tracker_error(&mut self, tracker_key: TrackerKey, error: std::io::Error) {
        let tracker = match self.trackers.get_mut(tracker_key) {
            Some(tracker) => tracker,
            None => return,
        };

        tracker.next_announce = Instant::now() + Duration::from_secs(15);
        tracker.status = format!("error: {error}");
    }

    pub fn on_piece_read_success(&mut self, piece_idx: PieceIdx, piece_data: Bytes) {
        let piece_key = PieceKey::from_index(piece_idx);
        self.pieces[piece_key].disk_requested = false;

        //println!("received piece {piece_idx} from disk");
        if self.mode == TorrentMode::Checking {
            self.checking_piece_read_success(piece_idx, piece_data);
        } else {
            self.peer_serve_pending_requests_for_piece(piece_idx, piece_data);
        }
    }

    pub fn on_piece_read_error(&mut self, piece_idx: PieceIdx, error: std::io::Error) {
        let piece_key = PieceKey::from_index(piece_idx);
        self.pieces[piece_key].disk_requested = false;

        if self.mode == TorrentMode::Checking {
            self.checking_piece_read_failure(piece_idx, error);
        } else {
            println!("TODO: FAILED TO READ PIECE FROM DISK {piece_idx} {error}");
        }
    }

    pub fn on_piece_write_error(&mut self, piece_idx: PieceIdx, error: std::io::Error) {
        //println!("failed to write piece {piece_idx}: {error}");
        self.bitfield.unset_piece(piece_idx);
    }
}

impl TorrentState {
    fn process_peer_have(&mut self, peer_key: PeerKey, piece_idx: PieceIdx) {
        let peer = &mut self.peers[peer_key];
        let piece_key = PieceKey::from_index(piece_idx);
        if !self.pieces.contains_key(piece_key) {
            //println!("peer sent Have message with invalid piece index");
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
            //println!("peer sent invalid piece request");
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

    fn peers_broadcast_have(&mut self, piece_idx: PieceIdx) {
        for peer in self.peers.values() {
            self.queue
                .send(peer.key, wire::Message::Have { index: piece_idx });
        }
    }

    fn process_tracker_address_list(&mut self, mut addrs: Vec<SocketAddr>) {
        //println!("received peer list: {:#?}", addrs);
        while self.peers.len() < PEER_COUNT_LIMIT {
            let addr = match addrs.pop() {
                Some(addr) => addr,
                None => break,
            };
            self.process_connect_to_peer(addr);
        }
    }

    fn process_connect_to_peer(&mut self, addr: SocketAddr) {
        //println!("received request to connect to peer at {addr}");
        if self.mode != TorrentMode::Running {
            //println!("can't add peer while mode is not running");
            return;
        }

        if self.peer_with_addr_exists(addr) {
            //println!("peer with addr {addr} already exists, not connecting");
            return;
        }

        let key = self
            .peers
            .insert_with_key(|key| PeerState::new_outgoing(key, addr));
        self.queue.connect(key, addr);
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

        peer.network_stats.add_download(data_len);
        self.network_stats.add_download(data_len);
        self.attempt_finalize_piece(piece_key);
        self.request_chunks_from(peer_key);
    }

    fn checking_piece_read_success(&mut self, piece_idx: PieceIdx, data: Bytes) {
        self.checking_bitfield.set_piece(piece_idx);
        let hash = Sha1::hash(&data);
        let expected_hash = self.info.piece_hash(piece_idx).expect("piece must exist");
        if hash == expected_hash {
            self.bitfield.set_piece(piece_idx);
        } else {
            //println!("hash check failed");
        }
        self.checking_try_finish();
    }

    fn checking_piece_read_failure(&mut self, piece_idx: PieceIdx, error: std::io::Error) {
        //println!("checking piece {piece_idx} failed: {error}");
        self.checking_bitfield.set_piece(piece_idx);
        self.checking_try_finish();
    }

    fn checking_try_finish(&mut self) {
        tracing::info!(
            "checking: {}/{}",
            self.checking_bitfield.num_set(),
            self.checking_bitfield.len()
        );
        if !self.checking_bitfield.complete() {
            return;
        }
        tracing::info!("done checking torrent");
        self.mode = TorrentMode::Running;
    }

    fn peer_serve_pending_requests_for_piece(&mut self, piece_idx: PieceIdx, data: Bytes) {
        tracing::trace!("serving peer requests for piece {piece_idx}");
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
                let message = wire::Message::Piece {
                    index: piece_idx,
                    begin: request.begin,
                    data: data
                        .slice(request.begin as usize..(request.begin + request.length) as usize),
                };
                self.queue.send(peer.key, message);
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
            tracing::warn!("tracker with url {url} already exists");
            return;
        }

        tracing::info!("adding tracker {url}");
        let key = self.trackers.insert_with_key({
            let url = url.clone();
            move |key| TrackerState {
                url,
                key,
                next_announce: Instant::now(),
                status: Default::default(),
            }
        });
        self.queue.tracker_connect(key, url);
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
        tracker.next_announce = Instant::now() + Duration::from_secs(300);
        self.queue.announce(tracker.key, params.clone());
    }

    fn disk_request_piece(&mut self, piece_idx: PieceIdx) {
        //println!("requesting piece {piece_idx} from disk");
        let piece_key = PieceKey::from_index(piece_idx);
        let piece = &mut self.pieces[piece_key];
        if !piece.disk_requested {
            piece.disk_requested = true;
            self.queue.read(piece_idx);
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
            let piece_idx = piece_key.to_index();
            self.bitfield.set_piece(piece_idx);
            self.queue.write(piece_idx, data);
            self.peers_broadcast_have(piece_idx);
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
                //println!("updating interest {current_interest} -> {target_interest}");
                peer.local_interested = target_interest;
                if target_interest {
                    self.queue.send(peer.key, wire::Message::Interested);
                } else {
                    self.queue.send(peer.key, wire::Message::NotInterested);
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
                self.queue.send(peer.key, request_message_from_chunk(chunk));
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
        tracing::info!(addr = ?peer_addr, "peer disconnected");

        self.peer_cancel_all_chunks(peer_key);
        self.peers.remove(peer_key);
        self.queue.disconnect(peer_key);
    }

    fn peer_with_addr_exists(&self, addr: SocketAddr) -> bool {
        self.peers.values().any(|p| p.addr == addr)
    }
}

fn request_message_from_chunk(chunk: &ChunkState) -> wire::Message {
    wire::Message::Request {
        index: chunk.piece.to_index(),
        begin: chunk.offset,
        length: chunk.length,
    }
}

fn extract_tracker_urls(info: &TorrentInfo) -> Vec<String> {
    if info.trackers().is_empty() {
        vec![info.announce().clone()]
    } else {
        info.trackers().iter().cloned().collect()
    }
}

use std::path::{Path, PathBuf};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _},
    sync::mpsc,
};

use crate::{PieceIdx, TorrentInfo};

use super::{SessionMsg, SessionSender, TorrentKey};

type DiskSender = mpsc::UnboundedSender<DiskMsg>;
type DiskReceiver = mpsc::UnboundedReceiver<DiskMsg>;

enum DiskMsg {
    ReadPiece { idx: PieceIdx },
    WritePiece { idx: PieceIdx, data: Bytes },
}

#[derive(Debug)]
pub struct DiskProc {
    sender: DiskSender,
}

impl DiskProc {
    pub fn spawn(
        sender: SessionSender,
        torrent_key: TorrentKey,
        info: TorrentInfo,
        root: PathBuf,
    ) -> Self {
        let (disk_sender, disk_receiver) = mpsc::unbounded_channel();
        let state = State {
            sender,
            receiver: disk_receiver,
            torrent_key,
            info,
            root,
        };
        tokio::spawn(run(state));
        Self {
            sender: disk_sender,
        }
    }

    pub fn read(&self, piece_idx: PieceIdx) {
        self.send(DiskMsg::ReadPiece { idx: piece_idx });
    }

    pub fn write(&self, piece_idx: PieceIdx, data: Bytes) {
        self.send(DiskMsg::WritePiece {
            idx: piece_idx,
            data,
        });
    }

    fn send(&self, msg: DiskMsg) {
        self.sender
            .send(msg)
            .expect("disk task should not exist while sender exists")
    }
}

struct State {
    sender: SessionSender,
    receiver: DiskReceiver,
    torrent_key: TorrentKey,
    info: TorrentInfo,
    root: PathBuf,
}

async fn run(mut state: State) {
    while let Some(msg) = state.receiver.recv().await {
        match msg {
            DiskMsg::ReadPiece { idx } => read(&mut state, idx).await,
            DiskMsg::WritePiece { idx, data } => write(&mut state, idx, data).await,
        }
    }
}

async fn read(state: &mut State, idx: PieceIdx) {
    match attempt_read_piece(&state.info, idx).await {
        Ok(data) => {
            let _ = state.sender.send(SessionMsg::PieceReadSuccess {
                torrent_key: state.torrent_key,
                piece_idx: idx,
                piece_data: data,
            });
        }
        Err(error) => {
            let _ = state.sender.send(SessionMsg::PieceReadError {
                torrent_key: state.torrent_key,
                piece_idx: idx,
                error,
            });
        }
    }
}

async fn attempt_read_piece(info: &TorrentInfo, piece_idx: PieceIdx) -> std::io::Result<Bytes> {
    let piece_len = info.piece_length_from_index(piece_idx);

    let mut data = BytesMut::new();
    data.resize(piece_len as usize, 0);

    for range in info.files_from_piece(piece_idx) {
        let mut options = tokio::fs::OpenOptions::new();
        let mut file = options
            .create(false)
            .write(false)
            .read(true)
            .open(range.file.path())
            .await?;
        file.seek(std::io::SeekFrom::Start(range.file_start))
            .await?;
        file.read_exact(&mut data[range.piece_range()]).await?;
    }

    Ok(data.freeze())
}

async fn write(state: &mut State, idx: PieceIdx, data: Bytes) {
    for range in state.info.files_from_piece(idx) {
        match attempt_write_piece(
            range.file.path(),
            range.file_start,
            &data[range.piece_range()],
        )
        .await
        {
            Ok(_) => {}
            Err(error) => {
                let _ = state.sender.send(SessionMsg::PieceWriteError {
                    torrent_key: state.torrent_key,
                    piece_idx: idx,
                    error,
                });
                break;
            }
        }
    }
}

async fn attempt_write_piece(path: &Path, offset: u64, data: &[u8]) -> std::io::Result<()> {
    //println!("writing piece to {path:?} at offset {offset}");
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut options = tokio::fs::OpenOptions::new();
    let mut file = options
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    file.write_all(data).await?;
    Ok(())
}

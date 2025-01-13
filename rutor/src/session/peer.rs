use std::net::SocketAddr;

use tokio::{
    io::{AsyncWriteExt, BufWriter},
    net::TcpStream,
    sync::mpsc,
    task::AbortHandle,
};

use crate::{wire, PeerId, Sha1};

use super::{PeerIo, PeerKey, PeerReader, PeerWriter, SessionMsg, SessionSender, TorrentKey};

type PeerSender = mpsc::UnboundedSender<wire::Message>;
type PeerReceiver = mpsc::UnboundedReceiver<wire::Message>;

#[derive(Debug)]
pub struct PeerProc {
    sender: PeerSender,
}

impl PeerProc {
    pub fn accept(
        sender: SessionSender,
        torrent_key: TorrentKey,
        peer_key: PeerKey,
        info_hash: Sha1,
        local_peer_id: PeerId,
        peer_io: PeerIo,
    ) -> Self {
        let (peer_sender, peer_receiver) = mpsc::unbounded_channel();
        tokio::spawn(accept(
            sender,
            peer_receiver,
            torrent_key,
            peer_key,
            info_hash,
            local_peer_id,
            peer_io,
        ));
        Self {
            sender: peer_sender,
        }
    }

    pub fn connect(
        sender: SessionSender,
        torrent_key: TorrentKey,
        peer_key: PeerKey,
        info_hash: Sha1,
        local_peer_id: PeerId,
        address: SocketAddr,
    ) -> Self {
        let (peer_sender, peer_receiver) = mpsc::unbounded_channel();
        tokio::spawn(connect(
            sender,
            peer_receiver,
            torrent_key,
            peer_key,
            info_hash,
            local_peer_id,
            address,
        ));
        Self {
            sender: peer_sender,
        }
    }

    pub fn send(&self, message: wire::Message) {
        let _ = self.sender.send(message);
    }
}

async fn connect(
    sender: SessionSender,
    receiver: PeerReceiver,
    torrent_key: TorrentKey,
    peer_key: PeerKey,
    info_hash: Sha1,
    local_peer_id: PeerId,
    address: SocketAddr,
) {
    let mut stream = match TcpStream::connect(address).await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = sender.send(SessionMsg::PeerFailure {
                torrent_key,
                peer_key,
                error,
            });
            return;
        }
    };

    if let Err(error) = wire::write_handshake_async(
        &mut stream,
        &wire::Handshake {
            info_hash,
            peer_id: local_peer_id,
        },
    )
    .await
    {
        let _ = sender.send(SessionMsg::PeerFailure {
            torrent_key,
            peer_key,
            error,
        });
        return;
    }

    let handshake = match wire::read_handshake_async(&mut stream).await {
        Ok(handshake) => handshake,
        Err(error) => {
            let _ = sender.send(SessionMsg::PeerFailure {
                torrent_key,
                peer_key,
                error,
            });
            return;
        }
    };

    if handshake.info_hash != info_hash {
        let _ = sender.send(SessionMsg::PeerFailure {
            torrent_key,
            peer_key,
            error: std::io::Error::other("peer sent invalid info_hash in handshake"),
        });
        return;
    }

    let _ = sender.send(SessionMsg::PeerHandshake {
        torrent_key,
        peer_key,
        peer_id: handshake.peer_id,
    });

    let (reader, writer) = stream.into_split();
    spawn_reader_writer(
        sender,
        receiver,
        torrent_key,
        peer_key,
        PeerIo::new(reader, writer),
    );
}

async fn accept(
    sender: SessionSender,
    receiver: PeerReceiver,
    torrent_key: TorrentKey,
    peer_key: PeerKey,
    info_hash: Sha1,
    local_peer_id: PeerId,
    mut peer_io: PeerIo,
) {
    if let Err(error) = wire::write_handshake_async(
        &mut peer_io.writer,
        &wire::Handshake {
            info_hash,
            peer_id: local_peer_id,
        },
    )
    .await
    {
        let _ = sender.send(SessionMsg::PeerFailure {
            torrent_key,
            peer_key,
            error,
        });
        return;
    }
    spawn_reader_writer(sender, receiver, torrent_key, peer_key, peer_io);
}

fn spawn_reader_writer(
    sender: SessionSender,
    receiver: PeerReceiver,
    torrent_key: TorrentKey,
    peer_key: PeerKey,
    peer_io: PeerIo,
) {
    let reader_handle = tokio::spawn(reader_task(
        sender.clone(),
        torrent_key,
        peer_key,
        peer_io.reader,
    ))
    .abort_handle();
    tokio::spawn(writer_task(
        sender,
        receiver,
        torrent_key,
        peer_key,
        peer_io.writer,
        reader_handle,
    ));
}

async fn reader_task(
    sender: SessionSender,
    torrent_key: TorrentKey,
    peer_key: PeerKey,
    mut reader: PeerReader,
) {
    loop {
        match wire::read_message_async(&mut reader).await {
            Ok(message) => {
                let _ = sender.send(SessionMsg::PeerMessage {
                    torrent_key,
                    peer_key,
                    message,
                });
            }
            Err(error) => {
                let _ = sender.send(SessionMsg::PeerFailure {
                    torrent_key,
                    peer_key,
                    error,
                });
                return;
            }
        }
    }
}

async fn writer_task(
    sender: SessionSender,
    mut receiver: PeerReceiver,
    torrent_key: TorrentKey,
    peer_key: PeerKey,
    writer: PeerWriter,
    // this task will abort the writer in case the PeerSender is dropped
    reader_handle: AbortHandle,
) {
    let mut writer = BufWriter::new(writer);
    while let Some(message) = receiver.recv().await {
        let write_result = wire::write_message_async(&mut writer, &message).await;
        let flush_result = writer.flush().await;
        let result = write_result.and(flush_result);
        if let Err(error) = result {
            tracing::error!("failed to write message to peer {error}");
            let _ = sender.send(SessionMsg::PeerFailure {
                torrent_key,
                peer_key,
                error,
            });
            break;
        }
    }
    reader_handle.abort();
}

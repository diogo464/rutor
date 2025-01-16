use std::{net::SocketAddr, time::Duration};

use tokio::{
    net::{TcpListener, TcpStream},
    task::AbortHandle,
};

use crate::wire;

use super::{PeerIo, SessionMsg, SessionSender};

pub struct ListenerProc {
    handle: AbortHandle,
}

impl Drop for ListenerProc {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl ListenerProc {
    // TODO: bind listener here and return Result
    pub fn spawn(sender: SessionSender, addr: SocketAddr) -> Self {
        let handle = tokio::spawn(entry(sender, addr)).abort_handle();
        Self { handle }
    }
}

async fn entry(sender: SessionSender, addr: SocketAddr) {
    loop {
        if let Err(err) = run(sender.clone(), addr).await {
            tracing::error!("failed to run listener: {err}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn run(sender: SessionSender, addr: SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let _ = tokio::spawn(accept(sender.clone(), stream, addr));
            }
            Err(err) => {
                tracing::warn!("failed to accept connection: {err}");
            }
        }
    }
}

async fn accept(sender: SessionSender, mut stream: TcpStream, addr: SocketAddr) {
    let read_future = wire::read_handshake_async(&mut stream);
    let result = tokio::time::timeout(Duration::from_secs(5), read_future).await;
    let handshake = match result {
        Ok(Ok(handshake)) => handshake,
        Ok(Err(err)) => {
            tracing::warn!("failed to read handshake fromm {addr}: {err}");
            return;
        }
        Err(err) => {
            tracing::warn!("failed to read handshake fromm {addr}: {err}");
            return;
        }
    };

    let (reader, writer) = stream.into_split();
    let peer_io = PeerIo::new(reader, writer);
    let _ = sender.send(SessionMsg::ListenerIncoming {
        peer_id: handshake.peer_id,
        peer_addr: addr,
        info_hash: handshake.info_hash,
        peer_io,
    });
}

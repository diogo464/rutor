use std::time::Duration;

use tokio::{sync::mpsc, task::AbortHandle};

use crate::{tracker::TrackerClient, AnnounceParams};

use super::{SessionMsg, SessionSender, TorrentKey, TrackerKey};

type TrackerSender = mpsc::UnboundedSender<TrackerMsg>;
type TrackerReceiver = mpsc::UnboundedReceiver<TrackerMsg>;

enum TrackerMsg {
    Announce(AnnounceParams),
}

#[derive(Debug)]
pub struct TrackerProc {
    sender: TrackerSender,
    // use the abort handle to abort the task if it is in the middle of a sleep
    handle: AbortHandle,
}

impl Drop for TrackerProc {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl TrackerProc {
    pub fn spawn(
        sender: SessionSender,
        torrent_key: TorrentKey,
        tracker_key: TrackerKey,
        url: String,
    ) -> Self {
        let (tracker_sender, tracker_receiver) = mpsc::unbounded_channel();
        let handle = tokio::spawn(entry(
            sender,
            tracker_receiver,
            torrent_key,
            tracker_key,
            url,
        ))
        .abort_handle();
        Self {
            sender: tracker_sender,
            handle,
        }
    }

    pub fn announce(&self, params: &AnnounceParams) {
        self.send(TrackerMsg::Announce(params.clone()));
    }

    fn send(&self, msg: TrackerMsg) {
        self.sender
            .send(msg)
            .expect("tracker receiver should not exit")
    }
}

async fn entry(
    sender: SessionSender,
    mut receiver: TrackerReceiver,
    torrent_key: TorrentKey,
    tracker_key: TrackerKey,
    url: String,
) {
    const ERROR_SLEEP_DURATION: Duration = Duration::from_secs(2);

    'outer: loop {
        // empty the queue of tracker requests
        loop {
            match receiver.try_recv() {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break 'outer,
            };
        }

        let mut client = match TrackerClient::new(&url).await {
            Ok(client) => client,
            Err(error) => {
                let _ = sender.send(SessionMsg::TrackerError {
                    torrent_key,
                    tracker_key,
                    error,
                });
                tokio::time::sleep(ERROR_SLEEP_DURATION).await;
                continue;
            }
        };

        if let Err(error) = tracker_loop(
            &sender,
            &mut receiver,
            torrent_key,
            tracker_key,
            &mut client,
        )
        .await
        {
            let _ = sender.send(SessionMsg::TrackerError {
                tracker_key,
                torrent_key,
                error,
            });
            tokio::time::sleep(ERROR_SLEEP_DURATION).await;
            continue;
        }
    }
}

async fn tracker_loop(
    sender: &SessionSender,
    receiver: &mut TrackerReceiver,
    torrent_key: TorrentKey,
    tracker_key: TrackerKey,
    client: &mut TrackerClient,
) -> std::io::Result<()> {
    while let Some(msg) = receiver.recv().await {
        match msg {
            TrackerMsg::Announce(params) => {
                // TODO: make async
                let response = client.announce(&params).await?;
                let _ = sender.send(SessionMsg::TrackerAnnounce {
                    torrent_key,
                    tracker_key,
                    announce: response,
                });
            }
        }
    }
    Ok(())
}

use crate::serialize_register_command;
use crate::RegisterClient;
use crate::{AcknowledgmentTarget, RegisterCommand, SystemClient, SystemRegisterCommand};
use crate::{Broadcast, Send};
use log::warn;
use std::collections::HashSet;
use std::{collections::HashMap, sync::Arc};
use tokio::io::AsyncWriteExt;
use tokio::{
    sync::mpsc,
    time::{sleep, Duration},
};

use log::debug;
use uuid::Uuid;

pub struct SendLink {
    send_sender: mpsc::UnboundedSender<crate::Send>,
    bcast_sender: mpsc::UnboundedSender<crate::Broadcast>,
}

impl SendLink {
    pub fn new(
        send_sender: mpsc::UnboundedSender<crate::Send>,
        bcast_sender: mpsc::UnboundedSender<crate::Broadcast>,
    ) -> Self {
        Self {
            send_sender,
            bcast_sender,
        }
    }
}

#[async_trait::async_trait]
impl RegisterClient for SendLink {
    async fn send(&self, msg: Send) {
        self.send_sender.send(msg).unwrap();
    }

    async fn broadcast(&self, msg: Broadcast) {
        self.bcast_sender.send(msg).unwrap();
    }
}

pub struct AcknowledgeLink {
    ack_sender: mpsc::UnboundedSender<AcknowledgmentTarget>,
}

impl AcknowledgeLink {
    pub fn new(ack_sender: mpsc::UnboundedSender<AcknowledgmentTarget>) -> Self {
        Self { ack_sender }
    }
}

#[async_trait::async_trait]
impl SystemClient for AcknowledgeLink {
    async fn acknowledge(&self, target: AcknowledgmentTarget) {
        self.ack_sender.send(target).unwrap();
    }
}

async fn serialize_system_msg(
    msg: &Arc<SystemRegisterCommand>,
    hmac_key: &Arc<[u8; 64]>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    serialize_register_command(
        &RegisterCommand::System((**msg).clone()),
        &mut buf,
        &**hmac_key,
    )
    .await
    .unwrap();
    buf
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_message_dispatcher(
    self_rank: u8,
    max_rank: u8,
    hmac_key: Arc<[u8; 64]>,
    mut send_receiver: mpsc::UnboundedReceiver<Send>,
    mut bcast_receiver: mpsc::UnboundedReceiver<Broadcast>,
    self_sender: mpsc::UnboundedSender<SystemRegisterCommand>,
    mut ack_receiver: mpsc::UnboundedReceiver<AcknowledgmentTarget>,
    connection_senders: HashMap<u8, mpsc::UnboundedSender<Arc<Vec<u8>>>>,
) {
    // let mut msgs: HashMap<Uuid, Arc<Vec<u8>>> = HashMap::new();
    let mut msgs: HashMap<Uuid, (HashSet<u8>, Arc<Vec<u8>>)> = HashMap::new();
    loop {
        let sleep_task = tokio::time::sleep(tokio::time::Duration::from_secs(3));
        tokio::select! {
            _ = sleep_task => {
                debug!("retransmitting {} messages", msgs.len());
                for (targets, msg) in msgs.values() {
                    for target in targets {
                        connection_senders.get(target).unwrap().send(msg.clone()).unwrap();
                    }
                }
            }
            Some(cmd) = send_receiver.recv() => {
                let target = cmd.target as u8;
                if cmd.target as u8 == self_rank {
                    self_sender.send((*cmd.cmd).clone()).unwrap();
                    continue;
                }
                let buf = Arc::new(serialize_system_msg(&cmd.cmd, &hmac_key).await);
                connection_senders.get(&target).unwrap().send(buf).unwrap();
            }
            Some(cmd) = bcast_receiver.recv() => {
                let buf = Arc::new(serialize_system_msg(&cmd.cmd, &hmac_key).await);
                self_sender.send((*cmd.cmd).clone()).unwrap();
                let targets: HashSet<u8> = (1..=max_rank).filter(|x| *x != self_rank).collect();
                for target in targets.iter() {
                    connection_senders.get(target).unwrap().send(buf.clone()).unwrap();
                }
                if max_rank > 1 {
                    msgs.insert(cmd.cmd.header.msg_ident, (targets, buf.clone()));
                }
            }
            Some(ack) = ack_receiver.recv() => {
                if ack.target == self_rank {
                    continue;
                }
                let entry = msgs.entry(ack.msg_ident).and_modify(|e| {e.0.remove(&ack.target);});
                match entry {
                    std::collections::hash_map::Entry::Occupied(value) => {
                        let already_acked = max_rank as usize - value.get().0.len();
                        if already_acked > (max_rank as usize) / 2 {
                            value.remove();
                            debug!("Removed handle for {:?}", ack);
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(_) => {
                        debug!("could not remove message handle {:?}", ack);
                    }
                }
            }
        }
    }
}

pub(crate) async fn run_connection_handler(
    location: &(String, u16),
    mut receiver: mpsc::UnboundedReceiver<Arc<Vec<u8>>>,
) {
    const WAIT_FOR_CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
    let addr = format!("{}:{}", location.0, location.1);
    'outer: loop {
        let mut stream = match tokio::net::TcpStream::connect(&addr).await {
            Ok(stream) => stream,
            Err(_) => {
                warn!(
                    "Link worker could not connect to {:?}. Reconecting in {:?}",
                    location, WAIT_FOR_CONNECTION_TIMEOUT
                );
                sleep(WAIT_FOR_CONNECTION_TIMEOUT).await;
                continue;
            }
        };

        while let Some(msg) = receiver.recv().await {
            // RegisterClient should repeat request until it gets response,
            // so it's not a problem if loose single message here
            if stream.write_all(&*msg).await.is_err() {
                warn!("Could not write to {:?}. Restarting connection.", location);
                continue 'outer;
            };
        }
    }
}

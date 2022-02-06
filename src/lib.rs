mod atomic_register;
mod domain;
mod serialization;
mod stable_storage;
mod system;

pub mod link;
pub mod sectors_manager;

pub use crate::domain::*;
pub use atomic_register_public::*;
pub use register_client_public::*;
pub use sectors_manager_public::*;
pub use stable_storage_public::*;
pub use transfer_public::*;

use crate::system::run_register_process_impl;

pub async fn run_register_process(config: Configuration) {
    run_register_process_impl(config).await;
}

pub mod atomic_register_public {
    use crate::{
        ClientRegisterCommand, OperationComplete, RegisterClient, SectorsManager, StableStorage,
        SystemRegisterCommand,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use crate::atomic_register::AtomicRegisterImpl;

    pub(crate) type Callback = Box<
        dyn FnOnce(OperationComplete) -> Pin<Box<dyn Future<Output = ()> + std::marker::Send>>
            + std::marker::Send
            + Sync,
    >;

    pub const ATOMIC_REGISTER_INSTANCES_COUNT: usize = 30;

    #[async_trait::async_trait]
    pub trait AtomicRegister: Send + Sync {
        /// Send client command to the register. After it is completed, we expect
        /// callback to be called. Note that completion of client command happens after
        /// delivery of multiple system commands to the register, as the algorithm specifies.
        async fn client_command(
            &mut self,
            cmd: ClientRegisterCommand,
            operation_complete: Callback,
        );

        /// Send system command to the register.
        async fn system_command(&mut self, cmd: SystemRegisterCommand);
    }

    /// Idents are numbered starting at 1 (up to the number of processes in the system).
    /// Storage for atomic register algorithm data is separated into StableStorage.
    /// Communication with other processes of the system is to be done by register_client.
    /// And sectors must be stored in the sectors_manager instance.
    pub async fn build_atomic_register(
        self_ident: u8,
        metadata: Box<dyn StableStorage>,
        register_client: Arc<dyn RegisterClient>,
        sectors_manager: Arc<dyn SectorsManager>,
        processes_count: usize,
    ) -> Box<dyn AtomicRegister> {
        Box::new(
            AtomicRegisterImpl::new(
                self_ident,
                metadata,
                register_client,
                sectors_manager,
                processes_count,
            )
            .await,
        )
    }
}

pub mod sectors_manager_public {
    use crate::sectors_manager::SectorsManagerImpl;
    use crate::{SectorIdx, SectorVec};
    use std::path::PathBuf;
    use std::sync::Arc;

    #[async_trait::async_trait]
    pub trait SectorsManager: Send + Sync {
        /// Returns 4096 bytes of sector data by index.
        async fn read_data(&self, idx: SectorIdx) -> SectorVec;

        /// Returns timestamp and write rank of the process which has saved this data.
        /// Timestamps and ranks are relevant for atomic register algorithm, and are described
        /// there.
        async fn read_metadata(&self, idx: SectorIdx) -> (u64, u8);

        /// Writes a new data, along with timestamp and write rank to some sector.
        async fn write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8));
    }

    /// Path parameter points to a directory to which this method has exclusive access.
    pub fn build_sectors_manager(path: PathBuf) -> Arc<dyn SectorsManager> {
        Arc::new(SectorsManagerImpl::new(path))
    }
}

pub mod transfer_public {
    use crate::{serialization::CommandReader, RegisterCommand, MAGIC_NUMBER};
    use hmac::{Hmac, Mac, NewMac};
    use serde::{Deserialize, Serialize};
    use sha2::Sha256;
    use std::io::Error;
    use tokio::io::{AsyncRead, AsyncWrite};

    use crate::serialization::{NetPack, NetUnpack};

    const HMAC_TAG_LEN: usize = 32;

    #[derive(Serialize, Deserialize)]
    struct RegisterCommandInternal {
        magic_array: [u8; 4],
    }

    pub async fn deserialize_register_command(
        data: &mut (dyn AsyncRead + Send + Unpin),
        hmac_system_key: &[u8; 64],
        hmac_client_key: &[u8; 32],
    ) -> Result<(RegisterCommand, bool), Error> {
        let mut reader = CommandReader::new(data);

        loop {
            reader.read_until(&MAGIC_NUMBER).await?;
            reader.reset();
            if let Ok(Some(unpacked)) = RegisterCommand::unpack_impl(&mut reader).await {
                let hmac_key: &[u8] = match unpacked {
                    RegisterCommand::Client(_) => hmac_client_key,
                    RegisterCommand::System(_) => hmac_system_key,
                };
                let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).unwrap();
                mac.update(&MAGIC_NUMBER);
                mac.update(reader.get_buf());

                let expected_hmac_tag = mac.finalize().into_bytes();
                let read_hmac_tag = reader.read_n(HMAC_TAG_LEN).await?;

                return Ok((unpacked, expected_hmac_tag.as_slice() == read_hmac_tag));
            }
        }
    }

    pub async fn serialize_register_command(
        cmd: &RegisterCommand,
        writer: &mut (dyn AsyncWrite + Send + Unpin),
        hmac_key: &[u8],
    ) -> Result<(), Error> {
        cmd.pack(writer, hmac_key).await
    }
}

pub mod register_client_public {
    use tokio::sync::mpsc;
    use uuid::Uuid;

    use crate::{
        link::{run_connection_handler, run_message_dispatcher, AcknowledgeLink, SendLink},
        SystemRegisterCommand,
    };
    use std::{collections::HashMap, convert::TryInto, sync::Arc};

    #[async_trait::async_trait]
    /// We do not need any public implementation of this trait. It is there for use
    /// in AtomicRegister. In our opinion it is a safe bet to say some structure of
    /// this kind must appear in your solution.
    pub trait RegisterClient: core::marker::Send + core::marker::Sync {
        /// Sends a system message to a single process.
        async fn send(&self, msg: Send);

        /// Broadcasts a system message to all processes in the system, including self.
        async fn broadcast(&self, msg: Broadcast);
    }

    #[derive(Debug)]
    pub struct Broadcast {
        pub cmd: Arc<SystemRegisterCommand>,
    }

    #[derive(Debug)]
    pub struct Send {
        pub cmd: Arc<SystemRegisterCommand>,
        /// Identifier of the target process. Those start at 1.
        pub target: usize,
    }

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub struct AcknowledgmentTarget {
        pub target: u8,
        pub msg_ident: Uuid,
    }

    #[async_trait::async_trait]
    pub trait SystemClient: core::marker::Send + core::marker::Sync {
        async fn acknowledge(&self, target: AcknowledgmentTarget);
    }

    pub async fn build_register_client(
        tcp_locations: Vec<(String, u16)>,
        self_rank: u8,
        self_sender: mpsc::UnboundedSender<SystemRegisterCommand>,
        hmac_key: &[u8],
    ) -> (Arc<dyn SystemClient>, Arc<dyn RegisterClient>) {
        let max_rank = tcp_locations.len() as u8;
        let mut worker_channels = HashMap::new();
        for (location, target) in tcp_locations.into_iter().zip(1u8..) {
            if target == self_rank {
                continue;
            }
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(async move { run_connection_handler(&location, receiver).await });
            worker_channels.insert(target, sender);
        }

        let (bcast_sender, bcast_receiver) = mpsc::unbounded_channel();
        let (send_sender, send_receiver) = mpsc::unbounded_channel();
        let (ack_sender, ack_receiver) = mpsc::unbounded_channel();

        let arc_hmac_key = Arc::new(hmac_key.try_into().unwrap());
        tokio::spawn(async move {
            run_message_dispatcher(
                self_rank,
                max_rank,
                arc_hmac_key,
                send_receiver,
                bcast_receiver,
                self_sender,
                ack_receiver,
                worker_channels,
            )
            .await
        });

        let acknowledge_link = AcknowledgeLink::new(ack_sender);
        let send_link = SendLink::new(send_sender, bcast_sender);

        (Arc::new(acknowledge_link), Arc::new(send_link))
    }
}

pub mod stable_storage_public {
    use crate::stable_storage::StableStorageImpl;
    use std::path::PathBuf;

    #[async_trait::async_trait]
    /// A helper trait for small amount of durable metadata needed by the register algorithm
    /// itself. Again, it is only for AtomicRegister definition. StableStorage in unit tests
    /// is durable, as one could expect.
    pub trait StableStorage: Send + Sync {
        async fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String>;

        async fn get(&self, key: &str) -> Option<Vec<u8>>;
    }

    pub fn build_stable_storage(path: PathBuf) -> Box<dyn StableStorage> {
        Box::new(StableStorageImpl::new(path))
    }
}

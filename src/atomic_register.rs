use std::sync::Arc;

use crate::{
    AtomicRegister, Broadcast, Callback, ClientRegisterCommand, OperationComplete, OperationReturn,
    ReadReturn, RegisterClient, SectorVec, SectorsManager, Send, StableStorage, StatusCode,
    SystemCommandHeader, SystemRegisterCommand, SystemRegisterCommandContent,
};

use std::convert::TryInto;
use uuid::Uuid;

use log::debug;

pub struct AtomicRegisterImpl {
    // consts
    processes_count: usize,
    self_ident: u8,

    register_client: Arc<dyn RegisterClient>,
    sectors_manager: Arc<dyn SectorsManager>,
    metadata: Box<dyn StableStorage>,

    // there can be only single operation handled at a time
    callback: Option<CommandCallbackArgs>,

    // state
    read_ident: u64,
    reading: bool,
    writing: bool,
    read_val: Option<SectorVec>,
    write_val: Option<SectorVec>,
    write_phase: bool,
    read_list: Vec<Option<(u64, u8, SectorVec)>>,
    ack_list: Vec<bool>,
}

struct CommandCallbackArgs {
    callback: Callback,
    request_identifier: u64,
}

#[async_trait::async_trait]
impl AtomicRegister for AtomicRegisterImpl {
    async fn client_command(&mut self, cmd: ClientRegisterCommand, operation_complete: Callback) {
        self.client_command_impl(cmd, operation_complete).await
    }

    async fn system_command(&mut self, cmd: SystemRegisterCommand) {
        self.system_command_impl(cmd).await;
    }
}

impl AtomicRegisterImpl {
    pub async fn new(
        self_ident: u8,
        metadata: Box<dyn StableStorage>,
        register_client: Arc<dyn RegisterClient>,
        sectors_manager: Arc<dyn SectorsManager>,
        processes_count: usize,
    ) -> Self {
        let mut metadata = metadata;
        let read_ident = match read_read_ident(&metadata).await {
            Some(x) => x,
            None => {
                store_read_ident(&mut metadata, 0).await;
                0
            }
        };

        Self {
            processes_count,
            self_ident,
            read_ident,
            register_client,
            sectors_manager,
            metadata,
            callback: None,
            reading: false,
            writing: false,
            read_val: None,
            write_val: None,
            write_phase: false,
            read_list: vec![None; processes_count],
            ack_list: vec![false; processes_count],
        }
    }

    async fn client_command_impl(
        &mut self,
        cmd: ClientRegisterCommand,
        operation_complete: Callback,
    ) {
        debug!("Read {:?} from {}", &cmd, self.self_ident);
        let uuid = Uuid::new_v4();
        self.read_ident += 1;
        store_read_ident(&mut self.metadata, self.read_ident).await;

        match cmd.content {
            crate::ClientRegisterCommandContent::Read => {
                self.reading = true;
            }

            crate::ClientRegisterCommandContent::Write { data } => {
                self.write_val = Some(data);
                self.writing = true;
            }
        }

        self.register_client
            .broadcast(Broadcast {
                cmd: Arc::new(SystemRegisterCommand {
                    header: SystemCommandHeader {
                        process_identifier: self.self_ident,
                        msg_ident: uuid,
                        read_ident: self.read_ident,
                        sector_idx: cmd.header.sector_idx,
                    },
                    content: SystemRegisterCommandContent::ReadProc,
                }),
            })
            .await;
        self.callback = Some(CommandCallbackArgs {
            callback: operation_complete,
            request_identifier: cmd.header.request_identifier,
        });
    }

    /// Send system command to the register.
    async fn system_command_impl(&mut self, cmd: SystemRegisterCommand) {
        debug!("Read {:?} from {}", &cmd, self.self_ident);

        match cmd.content {
            crate::SystemRegisterCommandContent::ReadProc => {
                let header = SystemCommandHeader {
                    process_identifier: self.self_ident,
                    msg_ident: cmd.header.msg_ident,
                    read_ident: cmd.header.read_ident,
                    sector_idx: cmd.header.sector_idx,
                };

                let (timestamp, write_rank) = self
                    .sectors_manager
                    .read_metadata(cmd.header.sector_idx)
                    .await;
                let sector_data = self.sectors_manager.read_data(cmd.header.sector_idx).await;

                let content = SystemRegisterCommandContent::Value {
                    timestamp,
                    write_rank,
                    sector_data,
                };
                self.register_client
                    .send(Send {
                        cmd: Arc::new(SystemRegisterCommand { header, content }),
                        target: cmd.header.process_identifier as usize,
                    })
                    .await;
            }
            crate::SystemRegisterCommandContent::Value {
                timestamp,
                write_rank,
                sector_data,
            } => {
                if !self.write_phase && self.read_ident == cmd.header.read_ident {
                    self.read_list[cmd.header.process_identifier as usize - 1] =
                        Some((timestamp, write_rank, sector_data));
                    let read_count = self.read_list.iter().filter(|x| x.is_some()).count();

                    if (self.reading || self.writing) && read_count > self.processes_count / 2 {
                        debug!("Hit quorum for Value gathering phase: {:?}", &cmd.header);

                        let (local_timestamp, local_write_rank) = self
                            .sectors_manager
                            .read_metadata(cmd.header.sector_idx)
                            .await;
                        self.read_list[self.self_ident as usize - 1] = Some((
                            local_timestamp,
                            local_write_rank,
                            self.sectors_manager.read_data(cmd.header.sector_idx).await,
                        ));

                        let (max_timestamp, max_write_rank, max_rank_data) = self
                            .read_list
                            .iter()
                            .filter(|x| x.is_some())
                            .map(|x| x.as_ref().unwrap())
                            .max_by(|(ts1, wr1, _), (ts2, wr2, _)| ts1.cmp(ts2).then(wr1.cmp(wr2)))
                            .unwrap()
                            .clone();

                        self.read_val = Some(max_rank_data.clone());

                        fill_vec_with(&mut self.read_list, None);
                        fill_vec_with(&mut self.ack_list, false);
                        self.write_phase = true;

                        let header = SystemCommandHeader {
                            process_identifier: self.self_ident,
                            msg_ident: Uuid::new_v4(),
                            read_ident: cmd.header.read_ident,
                            sector_idx: cmd.header.sector_idx,
                        };

                        let content = if self.reading {
                            SystemRegisterCommandContent::WriteProc {
                                timestamp: max_timestamp,
                                write_rank: max_write_rank,
                                data_to_write: max_rank_data,
                            }
                        } else {
                            self.sectors_manager
                                .write(
                                    cmd.header.sector_idx,
                                    &(
                                        self.write_val.clone().unwrap(),
                                        max_timestamp + 1,
                                        self.self_ident,
                                    ),
                                )
                                .await;

                            SystemRegisterCommandContent::WriteProc {
                                timestamp: max_timestamp + 1,
                                write_rank: self.self_ident,
                                data_to_write: self.write_val.take().unwrap(),
                            }
                        };

                        self.register_client
                            .broadcast(Broadcast {
                                cmd: Arc::new(SystemRegisterCommand { header, content }),
                            })
                            .await;
                    }
                }
            }
            crate::SystemRegisterCommandContent::WriteProc {
                timestamp,
                write_rank,
                data_to_write,
            } => {
                let (local_timestamp, local_write_rank) = self
                    .sectors_manager
                    .read_metadata(cmd.header.sector_idx)
                    .await;

                if (timestamp, write_rank) > (local_timestamp, local_write_rank) {
                    self.sectors_manager
                        .write(
                            cmd.header.sector_idx,
                            &(data_to_write, timestamp, write_rank),
                        )
                        .await;
                }

                let header = SystemCommandHeader {
                    process_identifier: self.self_ident,
                    msg_ident: cmd.header.msg_ident,
                    read_ident: cmd.header.read_ident,
                    sector_idx: cmd.header.sector_idx,
                };

                self.register_client
                    .send(Send {
                        cmd: Arc::new(SystemRegisterCommand {
                            header,
                            content: SystemRegisterCommandContent::Ack,
                        }),
                        target: cmd.header.process_identifier as usize,
                    })
                    .await;
            }
            crate::SystemRegisterCommandContent::Ack => {
                if self.write_phase && cmd.header.read_ident == self.read_ident {
                    self.ack_list[(cmd.header.process_identifier - 1) as usize] = true;
                    let ack_count = self.ack_list.iter().filter(|x| **x).count();
                    if (self.reading || self.writing) && ack_count > self.processes_count / 2 {
                        debug!("Hit quorum for Ack gathering phase: {:?}", &cmd.header);
                        fill_vec_with(&mut self.ack_list, false);
                        self.write_phase = false;
                        let operation_return = if self.reading {
                            self.reading = false;
                            OperationReturn::Read(ReadReturn {
                                read_data: Some(self.read_val.take().unwrap_or_else(|| {
                                    panic!("Could not read data for request: {:?}", cmd)
                                })),
                            })
                        } else {
                            self.writing = false;
                            OperationReturn::Write
                        };

                        match self.callback.take() {
                            Some(CommandCallbackArgs {
                                callback,
                                request_identifier,
                            }) => {
                                let op_complete = OperationComplete {
                                    status_code: StatusCode::Ok,
                                    request_identifier,
                                    op_return: operation_return,
                                };
                                callback(op_complete).await;
                            }
                            None => {
                                panic!("Could not find callback for header: {:?}", cmd.header);
                            }
                        };
                    }
                }
            }
        }
    }
}

fn fill_vec_with<T>(v: &mut Vec<T>, t: T)
where
    T: Clone,
{
    v.iter_mut().map(|x| *x = t.clone()).count();
}

macro_rules! accessor {
    ($setter:ident, $getter:ident, $key:expr, $ty:ty) => {
        async fn $setter(metadata: &mut Box<dyn StableStorage>, val: $ty) {
            metadata.put($key, &val.to_ne_bytes()).await.unwrap();
        }
        async fn $getter(metadata: &Box<dyn StableStorage>) -> Option<$ty> {
            metadata
                .get($key)
                .await
                .map(|x| <$ty>::from_ne_bytes(x.try_into().unwrap()))
        }
    };
}

accessor!(store_read_ident, read_read_ident, "read_ident", u64);

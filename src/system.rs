use crate::serialization::NetPack;
use crate::{
    build_atomic_register, build_register_client, build_sectors_manager, build_stable_storage,
    deserialize_register_command, AtomicRegister, Callback, ClientRegisterCommand,
    ClientRegisterCommandContent, Configuration, OperationComplete, OperationReturn, ReadReturn,
    RegisterCommand, StatusCode, SystemRegisterCommand, SystemRegisterCommandContent,
    ATOMIC_REGISTER_INSTANCES_COUNT,
};
use crate::{AcknowledgmentTarget, SystemClient};
use log::{debug, info, warn};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

fn check_sector_idx(cmd: &RegisterCommand, max_sector: u64) -> bool {
    match cmd {
        RegisterCommand::Client(ClientRegisterCommand { header, content: _ }) => {
            header.sector_idx < max_sector
        }
        RegisterCommand::System(SystemRegisterCommand { header, content: _ }) => {
            header.sector_idx < max_sector
        }
    }
}

async fn run_registers(
    registers: Vec<Box<dyn AtomicRegister>>,
    system_client: Arc<dyn SystemClient>,
    mut system_client_receiver: mpsc::UnboundedReceiver<(ClientRegisterCommand, Callback)>,
    mut system_system_receiver: mpsc::UnboundedReceiver<SystemRegisterCommand>,
) {
    let mut registers_channels_client: Vec<
        mpsc::UnboundedSender<(ClientRegisterCommand, Callback)>,
    > = Vec::new();
    let mut registers_channels_system: Vec<mpsc::UnboundedSender<SystemRegisterCommand>> =
        Vec::new();
    for mut register in registers.into_iter() {
        let (register_client_send, mut register_client_recv) = mpsc::unbounded_channel();
        let (register_system_send, mut register_system_recv) = mpsc::unbounded_channel();
        let (coin_send, mut coin_recv) = mpsc::unbounded_channel();

        registers_channels_client.push(register_client_send);
        registers_channels_system.push(register_system_send);

        let system_client_clone = system_client.clone();
        tokio::spawn(async move {
            let mut client_command_active = false;
            loop {
                tokio::select! {
                    // condition is evaluated before awaiting future
                    Some((cmd, callback)) = register_client_recv.recv(), if !client_command_active => {
                        client_command_active = true;
                        let coin_send = coin_send.clone();
                        let callback: Callback = Box::new(|response: OperationComplete| {
                            Box::pin(async move {
                                coin_send.send(()).unwrap();
                                callback(response).await;
                            })
                        });
                        register.client_command(cmd, callback).await;
                    }
                    Some(cmd) = register_system_recv.recv() => {
                        let a = match cmd.content  {
                            SystemRegisterCommandContent::Ack | SystemRegisterCommandContent::Value {..} => Some (
                                AcknowledgmentTarget {
                                    target: cmd.header.process_identifier,
                                    msg_ident: cmd.header.msg_ident
                                }
                            ),
                            _ => None
                        };
                        register.system_command(cmd).await;
                        if let Some(ack) = a {
                            system_client_clone.acknowledge(ack).await;
                        }
                    }
                    Some(_) = coin_recv.recv() => {
                        client_command_active = false;
                    }
                };
            }
        });
    }

    tokio::spawn(async move {
        let channels_num = registers_channels_system.len();
        loop {
            tokio::select! {
                Some((cmd, callback)) = system_client_receiver.recv() => {
                    let idx = cmd.header.sector_idx as usize;
                    if registers_channels_client[idx % channels_num].send((cmd, callback)).is_err() {
                        panic!("Could not send client message to {} atomic register", idx % channels_num);
                    }
                    // TODO Add unwrap
                },
                Some(cmd) = system_system_receiver.recv() => {
                        let idx = cmd.header.sector_idx as usize;
                        registers_channels_system[idx % channels_num]
                            .send(cmd)
                            .unwrap();
                }
            };
        }
    });
}

pub async fn run_register_process_impl(config: Configuration) {
    let tcp_locations_len = config.public.tcp_locations.len();

    let (host, addr) = &config.public.tcp_locations[config.public.self_rank as usize - 1];
    let addr_raw = format!("{}:{}", host, addr);
    let listener = TcpListener::bind(addr_raw.clone()).await.unwrap();

    let sectors_manager_dir = config.public.storage_dir.join("sectors_manager");
    tokio::fs::create_dir_all(&sectors_manager_dir)
        .await
        .unwrap();
    let sectors_manager = build_sectors_manager(sectors_manager_dir);

    let (system_sender, system_receiver) = mpsc::unbounded_channel();
    let (client_sender, client_receiver) = mpsc::unbounded_channel();

    let (system_client, register_client) = build_register_client(
        config.public.tcp_locations,
        config.public.self_rank,
        system_sender.clone(),
        &config.hmac_system_key,
    )
    .await;
    let mut registers = Vec::new();

    for ident in 0..ATOMIC_REGISTER_INSTANCES_COUNT {
        let path = config
            .public
            .storage_dir
            .join(format!("atomic_register_metadata_{}", ident));
        tokio::fs::create_dir_all(&path).await.unwrap();

        let metadata = build_stable_storage(path);
        registers.push(
            build_atomic_register(
                config.public.self_rank,
                metadata,
                register_client.clone(),
                sectors_manager.clone(),
                tcp_locations_len,
            )
            .await,
        );
    }

    run_registers(registers, system_client, client_receiver, system_receiver).await;

    let stream_handlers_args = Arc::new(StreamHandlerArgs {
        hmac_system_key: config.hmac_system_key,
        hmac_client_key: config.hmac_client_key,
        max_sector: config.public.max_sector,
    });

    info!("Listening on {}", addr_raw);
    while let Ok((stream, _incoming_addr)) = listener.accept().await {
        info!("Got connection from {}", _incoming_addr);
        let stream_handlers_args = stream_handlers_args.clone();
        let client_sender = client_sender.clone();
        let system_sender = system_sender.clone();
        tokio::spawn(async move {
            run_connection_handler(stream, stream_handlers_args, client_sender, system_sender)
                .await;
        });
    }
    info!("Done listening on {}", addr_raw);
}

struct StreamHandlerArgs {
    hmac_system_key: [u8; 64],
    hmac_client_key: [u8; 32],
    max_sector: u64,
}

async fn run_connection_handler(
    stream: TcpStream,
    args: Arc<StreamHandlerArgs>,
    client_sender: mpsc::UnboundedSender<(ClientRegisterCommand, Callback)>,
    system_sender: mpsc::UnboundedSender<SystemRegisterCommand>,
) {
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    let (write_half_sender, mut write_half_receiver): (
        mpsc::UnboundedSender<OperationComplete>,
        mpsc::UnboundedReceiver<OperationComplete>,
    ) = mpsc::unbounded_channel();

    let args_clone = args.clone();
    tokio::spawn(async move {
        while let Some(cmd) = write_half_receiver.recv().await {
            if cmd
                .pack(&mut write_half, &args_clone.hmac_client_key)
                .await
                .is_err()
            {
                // callback code can't just unwrap send result. Client could disconnect without waiting for response, finishing this task.
                break;
            }
        }
    });

    while let Ok((msg, hmac_ok)) =
        deserialize_register_command(&mut read_half, &args.hmac_system_key, &args.hmac_client_key)
            .await
    {
        if !hmac_ok {
            warn!("Got messsage with invalid hmac");
            debug!("Invalid hmac message: {:?}", msg);

            let response = match &msg {
                RegisterCommand::Client(ClientRegisterCommand { header, content }) => {
                    OperationComplete {
                        status_code: StatusCode::AuthFailure,
                        request_identifier: header.request_identifier,
                        op_return: match content {
                            ClientRegisterCommandContent::Read => {
                                OperationReturn::Read(ReadReturn { read_data: None })
                            }
                            ClientRegisterCommandContent::Write { .. } => OperationReturn::Write,
                        },
                    }
                }
                RegisterCommand::System(_) => continue,
            };

            write_half_sender.send(response).unwrap();
            continue;
        }

        if !check_sector_idx(&msg, args.max_sector) {
            warn!(
                "Got messsage with sector invalid sector: {:?}. Max sector: {}",
                &msg, args.max_sector
            );
            continue;
        }

        match msg {
            RegisterCommand::Client(cmd) => {
                let write_half_sender = write_half_sender.clone();
                let callback: Callback = Box::new(|response: OperationComplete| {
                    Box::pin(async move {
                        if write_half_sender.send(response).is_err() {
                            debug!("Could not sent response. Client probably disconected.");
                        }
                    })
                });
                if client_sender.send((cmd, callback)).is_err() {
                    panic!("Could not send client message to atomic register");
                }
            }
            RegisterCommand::System(cmd) => {
                system_sender
                    .send(cmd)
                    .expect("Could not send system message to atomic register");
            }
        };
    }
}

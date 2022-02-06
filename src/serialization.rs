use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use std::{convert::TryInto, io::Error};

use crate::{
    ClientCommandHeader, ClientRegisterCommand, ClientRegisterCommandContent, OperationComplete,
    OperationReturn, RegisterCommand, SectorVec, SystemCommandHeader, SystemCommandResponse,
    SystemCommandResponseContent, SystemCommandResponseHeader, SystemRegisterCommand,
    SystemRegisterCommandContent, MAGIC_NUMBER,
};

#[async_trait::async_trait]
pub trait NetPack {
    async fn pack(
        &self,
        writer: &mut (dyn AsyncWrite + Send + Unpin),
        hmac_key: &[u8],
    ) -> Result<(), Error> {
        let mut buf: Vec<u8> = Vec::new();
        self.pack_impl(&mut buf).await?;
        let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).unwrap();
        mac.update(&buf);
        let tag = mac.finalize();
        buf.extend_from_slice(&tag.into_bytes());
        writer.write_all(&buf).await
    }

    async fn pack_impl(&self, writer: &mut (dyn AsyncWrite + Send + Unpin)) -> Result<(), Error>;
}

#[async_trait::async_trait]
pub trait NetUnpack: Sized + Send + std::fmt::Debug {
    const HMAC_TAG_LEN: usize = 32;
    async fn unpack(
        reader: &mut (dyn AsyncRead + Send + Unpin),
        hmac_key: &[u8],
    ) -> Result<(Self, bool), Error> {
        let mut reader = CommandReader::new(reader);

        loop {
            reader.read_until(&MAGIC_NUMBER).await?;
            reader.reset();
            if let Ok(Some(unpacked)) = Self::unpack_impl(&mut reader).await {
                let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).unwrap();
                mac.update(&MAGIC_NUMBER);
                mac.update(reader.get_buf());

                let expected_hmac_tag = mac.finalize().into_bytes();
                let read_hmac_tag = reader.read_n(Self::HMAC_TAG_LEN).await?;

                return Ok((unpacked, expected_hmac_tag.as_slice() == read_hmac_tag));
            }
        }
    }

    async fn unpack_impl(reader: &mut CommandReader) -> Result<Option<Self>, Error> {
        let buf = reader.read_n(4).await?.to_vec();
        let msg_type = buf[3];
        if !Self::check_header(msg_type) {
            return Ok(None);
        }
        Self::unpack_with_header(reader, &buf.try_into().unwrap()).await
    }

    async fn unpack_with_header(
        reader: &mut CommandReader,
        header: &[u8; 4],
    ) -> Result<Option<Self>, Error>;

    fn check_header(msg_type: u8) -> bool;
}

trait MsgType {
    fn msg_type(&self) -> u8;
}

pub struct CommandReader<'a> {
    reader: &'a mut (dyn AsyncRead + Send + Unpin),
    buf: Vec<u8>,
    bytes_read: usize,
}

impl<'a> CommandReader<'a> {
    pub fn new(reader: &'a mut (dyn AsyncRead + Send + Unpin)) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            bytes_read: 0,
        }
    }

    pub fn get_buf(&self) -> &[u8] {
        &self.buf[..self.buf.len()]
    }

    pub async fn read_n(&mut self, n: usize) -> Result<&[u8], Error> {
        self.buf.resize(self.bytes_read + n, 0);

        self.bytes_read += self
            .reader
            .read_exact(&mut self.buf[self.bytes_read..self.bytes_read + n])
            .await?;

        Ok(&self.buf[self.bytes_read - n..self.bytes_read])
    }

    pub async fn read_until(&mut self, pattern: &[u8]) -> Result<usize, Error> {
        let mut bytes_read = 0;
        let pattern_len = pattern.len();
        let mut buf = vec![0; pattern_len];

        bytes_read += self.reader.read_exact(&mut buf).await?;

        loop {
            if pattern == buf {
                return Ok(bytes_read);
            }
            buf.rotate_left(1);
            let b = &mut buf[pattern_len - 1..];
            bytes_read += self.reader.read_exact(b).await?;
        }
    }

    pub fn reset(&mut self) {
        self.buf.clear();
        self.bytes_read = 0;
    }
}

impl MsgType for OperationComplete {
    fn msg_type(&self) -> u8 {
        match &self.op_return {
            OperationReturn::Read(_) => 0x41,
            OperationReturn::Write => 0x42,
        }
    }
}

#[async_trait::async_trait]
impl NetPack for OperationComplete {
    async fn pack_impl(&self, writer: &mut (dyn AsyncWrite + Send + Unpin)) -> Result<(), Error> {
        writer.write_all(&MAGIC_NUMBER).await?;
        writer.write_all(&[0_u8, 0]).await?;
        writer.write_all(&[self.status_code as u8]).await?;
        writer.write_all(&[self.msg_type()]).await?;
        writer
            .write_all(&self.request_identifier.to_be_bytes())
            .await?;

        match &self.op_return {
            OperationReturn::Read(read_data) => {
                if let Some(data) = &read_data.read_data {
                    writer.write_all(&data.0).await?;
                }
            }
            OperationReturn::Write => {}
        }

        Ok(())
    }
}

mod client {
    pub const COMMMAND_NUMBER_READ: u8 = 0x01;
    pub const COMMMAND_NUMBER_WRITE: u8 = 0x02;

    pub const COMMMAND_CONTENT_LEN: usize = 4096;
    pub const REQUEST_NUMBER_LEN: usize = 8;
    pub const SECTOR_INDEX_LEN: usize = 8;
}

mod system {
    pub const COMMMAND_NUMBER_READ_PROC: u8 = 0x03;
    pub const COMMMAND_NUMBER_VALUE: u8 = 0x04;
    pub const COMMMAND_NUMBER_WRITE_PROC: u8 = 0x05;
    pub const COMMMAND_NUMBER_ACK: u8 = 0x06;

    pub const UUID_LEN: usize = 16;
    pub const READ_IDENT_LEN: usize = 8;
    pub const SECTOR_INDEX_LEN: usize = 8;
    pub const TIMESTAMP_LEN: usize = 8;
    pub const VALUE_WR_LEN: usize = 1;
    pub const SECTOR_DATA_LEN: usize = 4096;
}

impl MsgType for SystemCommandResponseContent {
    fn msg_type(&self) -> u8 {
        match self {
            SystemCommandResponseContent::ReadProcAck => 0x43,
            SystemCommandResponseContent::ValueAck => 0x44,
            SystemCommandResponseContent::WriteProcAck => 0x45,
            SystemCommandResponseContent::AckAck => 0x46,
        }
    }
}

impl SystemCommandResponseContent {
    pub fn from_msg_type(msg_type: u8) -> Option<SystemCommandResponseContent> {
        match msg_type {
            0x43 => Some(SystemCommandResponseContent::ReadProcAck),
            0x44 => Some(SystemCommandResponseContent::ValueAck),
            0x45 => Some(SystemCommandResponseContent::WriteProcAck),
            0x46 => Some(SystemCommandResponseContent::AckAck),
            _ => None,
        }
    }
}

#[async_trait::async_trait]
impl NetPack for RegisterCommand {
    async fn pack_impl(&self, writer: &mut (dyn AsyncWrite + Send + Unpin)) -> Result<(), Error> {
        match self {
            RegisterCommand::Client(cmd) => cmd.pack_impl(writer).await,
            RegisterCommand::System(cmd) => cmd.pack_impl(writer).await,
        }
    }
}

#[async_trait::async_trait]
impl NetUnpack for RegisterCommand {
    fn check_header(msg_type: u8) -> bool {
        ClientRegisterCommand::check_header(msg_type)
            || SystemRegisterCommand::check_header(msg_type)
    }

    async fn unpack_with_header(
        reader: &mut CommandReader,
        header: &[u8; 4],
    ) -> Result<Option<Self>, Error> {
        let msg_type = header[3];

        if ClientRegisterCommand::check_header(msg_type) {
            ClientRegisterCommand::unpack_with_header(reader, header)
                .await
                .map(|x| x.map(RegisterCommand::Client))
        } else {
            SystemRegisterCommand::unpack_with_header(reader, header)
                .await
                .map(|x| x.map(RegisterCommand::System))
        }
    }
}

#[async_trait::async_trait]
impl NetPack for SystemRegisterCommand {
    async fn pack_impl(&self, writer: &mut (dyn AsyncWrite + Send + Unpin)) -> Result<(), Error> {
        writer.write_all(&MAGIC_NUMBER).await?;
        let msg_type: u8 = match self.content {
            SystemRegisterCommandContent::ReadProc => 3,
            SystemRegisterCommandContent::Value { .. } => 4,
            SystemRegisterCommandContent::WriteProc { .. } => 5,
            SystemRegisterCommandContent::Ack => 6,
        };

        writer.write_all(&[0_u8; 2]).await?;
        writer
            .write_all(&self.header.process_identifier.to_be_bytes())
            .await?;
        writer.write_all(&msg_type.to_be_bytes()).await?;
        writer.write_all(self.header.msg_ident.as_bytes()).await?;
        writer
            .write_all(&self.header.read_ident.to_be_bytes())
            .await?;
        writer
            .write_all(&self.header.sector_idx.to_be_bytes())
            .await?;

        if let SystemRegisterCommandContent::Value {
            timestamp,
            write_rank,
            sector_data: data,
        }
        | SystemRegisterCommandContent::WriteProc {
            timestamp,
            write_rank,
            data_to_write: data,
        } = &self.content
        {
            writer.write_all(&timestamp.to_be_bytes()).await?;
            writer.write_all(&[0_u8; 7]).await?;
            writer.write_all(&write_rank.to_be_bytes()).await?;
            writer.write_all(data.0.as_slice()).await?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl NetUnpack for SystemRegisterCommand {
    fn check_header(msg_type: u8) -> bool {
        msg_type == system::COMMMAND_NUMBER_VALUE
            || msg_type == system::COMMMAND_NUMBER_WRITE_PROC
            || msg_type == system::COMMMAND_NUMBER_READ_PROC
            || msg_type == system::COMMMAND_NUMBER_ACK
    }

    async fn unpack_with_header(
        reader: &mut CommandReader,
        header: &[u8; 4],
    ) -> Result<Option<Self>, Error> {
        let msg_type = header[3];
        let process_identifier = header[2];

        let buf = reader
            .read_n(system::UUID_LEN + system::READ_IDENT_LEN + system::SECTOR_INDEX_LEN)
            .await?;
        let (uuid_raw, read_ident_raw, sector_index_raw) = (
            &buf[..system::UUID_LEN],
            &buf[system::UUID_LEN..system::UUID_LEN + system::READ_IDENT_LEN],
            &buf[system::UUID_LEN + system::READ_IDENT_LEN
                ..system::UUID_LEN + system::READ_IDENT_LEN + system::SECTOR_INDEX_LEN],
        );

        let msg_ident = Uuid::from_bytes(uuid_raw.try_into().unwrap());
        let read_ident = u64::from_be_bytes(read_ident_raw.try_into().unwrap());
        let sector_idx = u64::from_be_bytes(sector_index_raw.try_into().unwrap());

        let header = SystemCommandHeader {
            process_identifier,
            msg_ident,
            read_ident,
            sector_idx,
        };

        let content = match msg_type {
            system::COMMMAND_NUMBER_VALUE | system::COMMMAND_NUMBER_WRITE_PROC => {
                let buf = reader
                    .read_n(
                        system::TIMESTAMP_LEN + 7 + system::VALUE_WR_LEN + system::SECTOR_DATA_LEN,
                    )
                    .await?;
                let (timestamp_raw, write_rank, sector_data) = (
                    &buf[..system::TIMESTAMP_LEN],
                    buf[system::TIMESTAMP_LEN + 7],
                    &buf[system::TIMESTAMP_LEN + 7 + system::VALUE_WR_LEN
                        ..system::TIMESTAMP_LEN
                            + 7
                            + system::VALUE_WR_LEN
                            + system::SECTOR_DATA_LEN],
                );

                let timestamp = u64::from_be_bytes(timestamp_raw.try_into().unwrap());

                match msg_type {
                    system::COMMMAND_NUMBER_VALUE => SystemRegisterCommandContent::Value {
                        timestamp,
                        write_rank,
                        sector_data: SectorVec(sector_data.to_vec()),
                    },
                    system::COMMMAND_NUMBER_WRITE_PROC => SystemRegisterCommandContent::WriteProc {
                        timestamp,
                        write_rank,
                        data_to_write: SectorVec(sector_data.to_vec()),
                    },
                    _ => unreachable!(),
                }
            }
            system::COMMMAND_NUMBER_READ_PROC => SystemRegisterCommandContent::ReadProc {},
            system::COMMMAND_NUMBER_ACK => SystemRegisterCommandContent::Ack {},
            _ => unreachable!(),
        };

        Ok(Some(SystemRegisterCommand { header, content }))
    }
}

#[async_trait::async_trait]
impl NetPack for ClientRegisterCommand {
    async fn pack_impl(&self, writer: &mut (dyn AsyncWrite + Send + Unpin)) -> Result<(), Error> {
        writer.write_all(&MAGIC_NUMBER).await?;
        let msg_type: u8 = match self.content {
            ClientRegisterCommandContent::Read => 1,
            ClientRegisterCommandContent::Write { .. } => 2,
        };

        writer.write_all(&[0_u8; 3]).await?;
        writer.write_all(&msg_type.to_be_bytes()).await?;
        writer
            .write_all(&self.header.request_identifier.to_be_bytes())
            .await?;
        writer
            .write_all(&self.header.sector_idx.to_be_bytes())
            .await?;

        if let ClientRegisterCommandContent::Write { data } = &self.content {
            writer.write_all(data.0.as_slice()).await?;
        };

        Ok(())
    }
}

#[async_trait::async_trait]
impl NetUnpack for ClientRegisterCommand {
    fn check_header(msg_type: u8) -> bool {
        msg_type == client::COMMMAND_NUMBER_READ || msg_type == client::COMMMAND_NUMBER_WRITE
    }

    async fn unpack_with_header(
        reader: &mut CommandReader,
        header: &[u8; 4],
    ) -> Result<Option<Self>, Error> {
        let msg_type = header[3];

        let header_raw = reader
            .read_n(client::REQUEST_NUMBER_LEN + client::SECTOR_INDEX_LEN)
            .await?;

        let header = ClientCommandHeader {
            request_identifier: u64::from_be_bytes(header_raw[..8].try_into().unwrap()),
            sector_idx: u64::from_be_bytes(header_raw[8..].try_into().unwrap()),
        };

        let content = if msg_type == client::COMMMAND_NUMBER_WRITE {
            let sector = reader.read_n(client::COMMMAND_CONTENT_LEN).await?;
            ClientRegisterCommandContent::Write {
                data: SectorVec(sector.to_vec()),
            }
        } else {
            ClientRegisterCommandContent::Read {}
        };

        Ok(Some(ClientRegisterCommand { header, content }))
    }
}

#[async_trait::async_trait]
impl NetPack for SystemCommandResponse {
    async fn pack_impl(&self, writer: &mut (dyn AsyncWrite + Send + Unpin)) -> Result<(), Error> {
        writer.write_all(&MAGIC_NUMBER).await?;
        writer.write_all(&[0_u8, 0]).await?;
        writer.write_all(&[self.header.process_rank]).await?;
        writer.write_all(&[self.content.msg_type()]).await?;
        writer.write_all(self.header.uuid.as_bytes()).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl NetUnpack for SystemCommandResponse {
    fn check_header(msg_type: u8) -> bool {
        msg_type == 0x43 || msg_type == 0x44 || msg_type == 0x45 || msg_type == 0x46
    }

    async fn unpack_with_header(
        reader: &mut CommandReader,
        header: &[u8; 4],
    ) -> Result<Option<Self>, Error> {
        let process_rank = header[2];
        let msg_type = header[3];

        if let Some(content) = SystemCommandResponseContent::from_msg_type(msg_type) {
            let uuid_raw = reader.read_n(16).await?;
            let uuid = Uuid::from_bytes(uuid_raw.try_into().unwrap());

            Ok(Some(SystemCommandResponse {
                header: SystemCommandResponseHeader { process_rank, uuid },
                content,
            }))
        } else {
            Ok(None)
        }
    }
}

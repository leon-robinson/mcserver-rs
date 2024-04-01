#![allow(clippy::unnecessary_wraps)]

use crate::{
    connection_handler::Connection,
    info,
    protocol::{
        ClientboundPacket, EncryptionResponse, HandshakePacket, LoginStart, PingRequest, Result,
        ServerboundPacket, State, StatusResponse,
    },
    warn,
};

// True if should keep connection alive, false if should close the connection.
pub type PacketHandler = fn(&mut Connection, i32) -> Result<bool>;

pub static PACKET_HANDLERS: [PacketHandler; 4] = [
    packet_handler_0x00,
    packet_handler_0x01,
    packet_handler_0x02,
    packet_handler_0x03,
];

fn packet_handler_0x00(connection: &mut Connection, _packet_len: i32) -> Result<bool> {
    match connection.state {
        State::Unset => {
            HandshakePacket::from_connection(connection)?.handle(connection)?;
        }
        State::Status => {
            // TODO: Cache the packet instead of creating it every request.
            let mut packet = StatusResponse::to_bytes(StatusResponse {
                version_name: "1.20.4".into(),
                version_protocol: 765,
                players_max: 20,
                players_online: 7,
                motd: "Test\nNew line".into(),
                favicon_b64: "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAABHNCSVQICAgIfAhkiAAAAIlJREFUeF7t1QERACAMAzHAv+fBYeODg/Uauue9FX4nfPs/XQAaEE8AgXgBfIIIIBBPAIF4AawAAgjEE0AgXgArgAAC8QQQiBfACiCAQDwBBOIFsAIIIBBPAIF4AawAAgjEE0AgXgArgAAC8QQQiBfACiCAQDwBBOIFsAIIIBBPAIF4AawAAnUCF1U6BHx5JYjsAAAAAElFTkSuQmCC".into(),
                enforces_secure_chat: false,
                previews_chat: true,
            })?;

            connection.write_bytes(packet.as_mut_slice())?;
            connection.flush()?;

            info!("Sent back StatusReponse packet.");
        }
        State::Login => {
            LoginStart::from_connection(connection)?.handle(connection)?;
        }
        State::Configuration => {
            warn!("Got 0x00 packet during State::Configuration");
        }
    }

    Ok(true)
}

fn packet_handler_0x01(connection: &mut Connection, _packet_len: i32) -> Result<bool> {
    match connection.state {
        State::Status => {
            PingRequest::from_connection(connection)?.handle(connection)?;
            return Ok(false);
        }
        State::Login => {
            EncryptionResponse::from_connection(connection)?.handle(connection)?;
        }
        _ => {
            warn!("Got packet_id 0x01 during state: '{}'", connection.state);
        }
    };

    Ok(true)
}

fn packet_handler_0x02(_connection: &mut Connection, _packet_len: i32) -> Result<bool> {
    Ok(true)
}

fn packet_handler_0x03(connection: &mut Connection, _packet_len: i32) -> Result<bool> {
    match connection.state {
        State::Login => {
            connection.login_acknowledged = true;
            connection.state = State::Configuration;
            info!("Received Login Acknowledged from the client, setting state to Configuration.");
        }
        _ => {
            warn!("Got packet 0x03 while not in Login state.");
        }
    }
    Ok(true)
}

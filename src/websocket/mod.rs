//! Captured WebSocket connections, frames, and live message injection.

use crate::domain::{DomainError, DomainResult, ErrorCode, ProjectId};
use crate::storage::{now_rfc3339, Db};
use base64::Engine;
use dashmap::DashMap;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

const MESSAGE_PRESENTATION_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct WebSocketConnection {
    pub id: i64,
    pub project_id: ProjectId,
    pub handshake_exchange_id: Option<i64>,
    pub url: String,
    pub protocol: Option<String>,
    pub state: String,
    pub opened_at: String,
    pub closed_at: Option<String>,
    pub message_count: u64,
    pub client_bytes: u64,
    pub server_bytes: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebSocketMessageRecord {
    pub id: i64,
    pub project_id: ProjectId,
    pub connection_id: i64,
    pub direction: String,
    pub opcode: String,
    pub payload_length: u64,
    pub truncated: bool,
    pub created_at: String,
    pub encoding: String,
    pub payload: String,
}

#[derive(Debug)]
pub struct InjectedMessage {
    pub to_server: bool,
    pub message: Message,
}

#[derive(Default)]
pub struct WebSocketService {
    active: DashMap<(i64, i64), mpsc::Sender<InjectedMessage>>,
}

impl WebSocketService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        project_id: ProjectId,
        connection_id: i64,
        sender: mpsc::Sender<InjectedMessage>,
    ) {
        self.active
            .insert((project_id.get(), connection_id), sender);
    }

    pub fn unregister(&self, project_id: ProjectId, connection_id: i64) {
        self.active.remove(&(project_id.get(), connection_id));
    }

    pub fn is_active(&self, project_id: ProjectId, connection_id: i64) -> bool {
        self.active.contains_key(&(project_id.get(), connection_id))
    }

    pub async fn send(
        &self,
        project_id: ProjectId,
        connection_id: i64,
        to_server: bool,
        encoding: &str,
        payload: &str,
    ) -> DomainResult<()> {
        let bytes = match encoding {
            "text" => payload.as_bytes().to_vec(),
            "base64" => base64::engine::general_purpose::STANDARD
                .decode(payload)
                .map_err(|error| DomainError::invalid(format!("payload base64: {error}")))?,
            _ => return Err(DomainError::invalid("encoding must be text or base64")),
        };
        let message = if encoding == "text" {
            Message::Text(
                String::from_utf8(bytes)
                    .map_err(|_| DomainError::invalid("text payload must be UTF-8"))?
                    .into(),
            )
        } else {
            Message::Binary(bytes.into())
        };
        let sender = self
            .active
            .get(&(project_id.get(), connection_id))
            .map(|entry| entry.value().clone())
            .ok_or_else(|| DomainError::not_found("active WebSocket connection"))?;
        sender
            .send(InjectedMessage { to_server, message })
            .await
            .map_err(|_| DomainError::new(ErrorCode::Unavailable, "WebSocket connection closed"))
    }
}

impl Db {
    pub async fn create_websocket_connection(
        &self,
        project_id: ProjectId,
        handshake_exchange_id: Option<i64>,
        url: String,
        protocol: Option<String>,
    ) -> DomainResult<WebSocketConnection> {
        let opened_at = now_rfc3339();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO websocket_connections
                 (project_id, handshake_exchange_id, url, protocol, opened_at)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    project_id.get(),
                    handshake_exchange_id,
                    url,
                    protocol,
                    opened_at
                ],
            )
            .map_err(storage_error)?;
            load_connection(conn, project_id, conn.last_insert_rowid())
        })
        .await
    }

    pub async fn close_websocket_connection(
        &self,
        project_id: ProjectId,
        connection_id: i64,
        error: Option<String>,
    ) -> DomainResult<()> {
        let closed_at = now_rfc3339();
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE websocket_connections SET state=?1, closed_at=?2, last_error=?3
                 WHERE project_id=?4 AND id=?5",
                params![
                    if error.is_some() { "failed" } else { "closed" },
                    closed_at,
                    error,
                    project_id.get(),
                    connection_id
                ],
            )
            .map_err(storage_error)?;
            Ok(())
        })
        .await
    }

    pub async fn insert_websocket_message(
        &self,
        project_id: ProjectId,
        connection_id: i64,
        direction: &str,
        opcode: &str,
        payload: &[u8],
        capture_limit: u64,
    ) -> DomainResult<i64> {
        let payload_length = payload.len() as u64;
        let kept = usize::try_from(capture_limit)
            .unwrap_or(usize::MAX)
            .min(payload.len());
        let stored = payload[..kept].to_vec();
        let truncated = kept < payload.len();
        let direction = direction.to_string();
        let opcode = opcode.to_string();
        let created_at = now_rfc3339();
        self.with_conn(move |conn| {
            let tx = conn.unchecked_transaction().map_err(storage_error)?;
            tx.execute(
                "INSERT INTO websocket_messages
                 (project_id, connection_id, direction, opcode, payload, payload_length, truncated, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![project_id.get(), connection_id, direction, opcode, stored,
                    i64::try_from(payload_length).unwrap_or(i64::MAX), truncated as i64, created_at],
            )
            .map_err(storage_error)?;
            let id = tx.last_insert_rowid();
            let client_bytes = if direction == "client_to_server" { payload_length } else { 0 };
            let server_bytes = if direction == "server_to_client" { payload_length } else { 0 };
            tx.execute(
                "UPDATE websocket_connections SET message_count=message_count+1,
                 client_bytes=client_bytes+?1, server_bytes=server_bytes+?2
                 WHERE project_id=?3 AND id=?4",
                params![i64::try_from(client_bytes).unwrap_or(i64::MAX),
                    i64::try_from(server_bytes).unwrap_or(i64::MAX), project_id.get(), connection_id],
            )
            .map_err(storage_error)?;
            tx.commit().map_err(storage_error)?;
            Ok(id)
        })
        .await
    }

    pub async fn list_websocket_connections(
        &self,
        project_id: ProjectId,
        limit: u32,
    ) -> DomainResult<Vec<WebSocketConnection>> {
        self.with_conn(move |conn| {
            let mut statement = conn
                .prepare(
                    "SELECT id, project_id, handshake_exchange_id, url, protocol, state,
                            opened_at, closed_at, message_count, client_bytes, server_bytes, last_error
                     FROM websocket_connections WHERE project_id=?1 ORDER BY id DESC LIMIT ?2",
                )
                .map_err(storage_error)?;
            let rows = statement
                .query_map(params![project_id.get(), limit.min(500)], connection_row)
                .map_err(storage_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)
        })
        .await
    }

    pub async fn list_websocket_messages(
        &self,
        project_id: ProjectId,
        connection_id: i64,
        after_id: Option<i64>,
        limit: u32,
    ) -> DomainResult<Vec<WebSocketMessageRecord>> {
        self.with_conn(move |conn| {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM websocket_connections WHERE project_id=?1 AND id=?2)",
                    params![project_id.get(), connection_id],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if !exists {
                return Err(DomainError::not_found("WebSocket connection"));
            }
            let mut statement = conn
                .prepare(
                    "SELECT id, project_id, connection_id, direction, opcode, payload,
                            payload_length, truncated, created_at
                     FROM websocket_messages
                     WHERE project_id=?1 AND connection_id=?2 AND id>?3
                     ORDER BY id LIMIT ?4",
                )
                .map_err(storage_error)?;
            let rows = statement
                .query_map(
                    params![project_id.get(), connection_id, after_id.unwrap_or(0), limit.min(1000)],
                    message_row,
                )
                .map_err(storage_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)
        })
        .await
    }
}

fn load_connection(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
    connection_id: i64,
) -> DomainResult<WebSocketConnection> {
    conn.query_row(
        "SELECT id, project_id, handshake_exchange_id, url, protocol, state,
                opened_at, closed_at, message_count, client_bytes, server_bytes, last_error
         FROM websocket_connections WHERE project_id=?1 AND id=?2",
        params![project_id.get(), connection_id],
        connection_row,
    )
    .optional()
    .map_err(storage_error)?
    .ok_or_else(|| DomainError::not_found("WebSocket connection"))
}

fn connection_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WebSocketConnection> {
    Ok(WebSocketConnection {
        id: row.get(0)?,
        project_id: ProjectId(row.get(1)?),
        handshake_exchange_id: row.get(2)?,
        url: row.get(3)?,
        protocol: row.get(4)?,
        state: row.get(5)?,
        opened_at: row.get(6)?,
        closed_at: row.get(7)?,
        message_count: row.get::<_, i64>(8)?.max(0) as u64,
        client_bytes: row.get::<_, i64>(9)?.max(0) as u64,
        server_bytes: row.get::<_, i64>(10)?.max(0) as u64,
        last_error: row.get(11)?,
    })
}

fn message_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WebSocketMessageRecord> {
    let payload: Vec<u8> = row.get(5)?;
    let (encoding, presented) = match std::str::from_utf8(&payload) {
        Ok(text) => ("text", text.to_string()),
        Err(_) => (
            "base64",
            base64::engine::general_purpose::STANDARD.encode(&payload),
        ),
    };
    let payload = if presented.len() > MESSAGE_PRESENTATION_BYTES {
        let mut end = MESSAGE_PRESENTATION_BYTES;
        while !presented.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &presented[..end])
    } else {
        presented
    };
    Ok(WebSocketMessageRecord {
        id: row.get(0)?,
        project_id: ProjectId(row.get(1)?),
        connection_id: row.get(2)?,
        direction: row.get(3)?,
        opcode: row.get(4)?,
        payload_length: row.get::<_, i64>(6)?.max(0) as u64,
        truncated: row.get::<_, i64>(7)? != 0,
        created_at: row.get(8)?,
        encoding: encoding.into(),
        payload,
    })
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

pub type SharedWebSocketService = Arc<WebSocketService>;

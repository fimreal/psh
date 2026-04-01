use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::{info, error, debug};
use chrono::Utc;
use serde::Serialize;

pub struct AuditLogger {
    log_path: PathBuf,
}

#[derive(Debug, Serialize)]
struct AuditEvent {
    timestamp: String,
    #[serde(rename = "type")]
    event_type: String,
    session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl AuditLogger {
    pub async fn new(log_path: &PathBuf) -> anyhow::Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = log_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        info!("Audit logger initialized: {:?}", log_path);

        Ok(Self {
            log_path: log_path.clone(),
        })
    }

    async fn write_event(&self, event: AuditEvent) -> anyhow::Result<()> {
        let line = serde_json::to_string(&event)?;
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await?;
        
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        
        debug!("Audit event logged: {}", event.event_type);
        Ok(())
    }

    pub async fn log_connection(&self, session_id: &str, host: &str, user: Option<&str>) -> anyhow::Result<()> {
        info!("Audit: Connection - session={}, host={}, user={:?}", session_id, host, user);
        
        self.write_event(AuditEvent {
            timestamp: Utc::now().to_rfc3339(),
            event_type: "connection".to_string(),
            session_id: session_id.to_string(),
            host: Some(host.to_string()),
            user: user.map(|s| s.to_string()),
            command: None,
            error: None,
        }).await
    }

    pub async fn log_disconnection(&self, session_id: &str, host: &str) -> anyhow::Result<()> {
        info!("Audit: Disconnection - session={}, host={}", session_id, host);
        
        self.write_event(AuditEvent {
            timestamp: Utc::now().to_rfc3339(),
            event_type: "disconnection".to_string(),
            session_id: session_id.to_string(),
            host: Some(host.to_string()),
            user: None,
            command: None,
            error: None,
        }).await
    }

    pub async fn log_error(&self, session_id: &str, host: Option<&str>, error: &str) -> anyhow::Result<()> {
        error!("Audit: Error - session={}, host={:?}, error={}", session_id, host, error);
        
        self.write_event(AuditEvent {
            timestamp: Utc::now().to_rfc3339(),
            event_type: "error".to_string(),
            session_id: session_id.to_string(),
            host: host.map(|s| s.to_string()),
            user: None,
            command: None,
            error: Some(error.to_string()),
        }).await
    }
}

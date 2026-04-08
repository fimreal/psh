use chrono::Utc;
use serde::Serialize;
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

pub struct AuditLogger {
    log_path: PathBuf,
    max_retries: u8,
}

#[derive(Debug, Serialize, Clone)]
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
            max_retries: 3,
        })
    }

    async fn write_event(&self, event: &AuditEvent) -> anyhow::Result<()> {
        let line = serde_json::to_string(event)?;
        let mut last_error = None;

        // Retry logic for robustness
        for attempt in 1..=self.max_retries {
            match self.try_write(&line).await {
                Ok(()) => {
                    debug!("Audit event logged: {}", event.event_type);
                    return Ok(());
                }
                Err(e) => {
                    warn!("Audit log write attempt {} failed: {}", attempt, e);
                    last_error = Some(e);
                    if attempt < self.max_retries {
                        tokio::time::sleep(std::time::Duration::from_millis(100 * attempt as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Failed to write audit log")))
    }

    async fn try_write(&self, line: &str) -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await?;

        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }

    pub async fn log_connection(
        &self,
        session_id: &str,
        host: &str,
        user: Option<&str>,
    ) -> anyhow::Result<()> {
        info!(
            "Audit: Connection - session={}, host={}, user={:?}",
            session_id, host, user
        );

        self.write_event(&AuditEvent {
            timestamp: Utc::now().to_rfc3339(),
            event_type: "connection".to_string(),
            session_id: session_id.to_string(),
            host: Some(host.to_string()),
            user: user.map(|s| s.to_string()),
            command: None,
            error: None,
        })
        .await
    }

    pub async fn log_disconnection(&self, session_id: &str, host: &str) -> anyhow::Result<()> {
        info!(
            "Audit: Disconnection - session={}, host={}",
            session_id, host
        );

        self.write_event(&AuditEvent {
            timestamp: Utc::now().to_rfc3339(),
            event_type: "disconnection".to_string(),
            session_id: session_id.to_string(),
            host: Some(host.to_string()),
            user: None,
            command: None,
            error: None,
        })
        .await
    }
}

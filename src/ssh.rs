use anyhow::Result;
use russh_keys::key;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

pub struct SshManager {
    config_path: PathBuf,
    hosts: Arc<Mutex<HashMap<String, HostConfig>>>,
}

#[derive(Clone, Debug)]
pub struct HostConfig {
    pub name: String,
    pub hostname: String,
    pub user: Option<String>,
    pub port: u16,
    pub identity_file: Option<PathBuf>,
}

impl SshManager {
    pub async fn new(config_path: &PathBuf) -> Result<Self> {
        info!("Initializing SSH manager with config: {:?}", config_path);

        let manager = Self {
            config_path: config_path.clone(),
            hosts: Arc::new(Mutex::new(HashMap::new())),
        };

        if config_path.exists() {
            manager.parse_ssh_config().await?;
        } else {
            warn!("SSH config file not found at {:?}", config_path);
        }

        Ok(manager)
    }

    pub async fn list_hosts_detailed(&self) -> Result<Vec<HostConfig>> {
        let hosts = self.hosts.lock().await;
        Ok(hosts.values().cloned().collect())
    }

    pub async fn get_host_config(&self, name: &str) -> Option<HostConfig> {
        let hosts = self.hosts.lock().await;
        hosts.get(name).cloned()
    }

    async fn parse_ssh_config(&self) -> Result<()> {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let file = tokio::fs::File::open(&self.config_path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut current_host: Option<HostConfig> = None;
        let mut hosts = self.hosts.lock().await;

        while let Some(line) = lines.next_line().await? {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let keyword = parts[0].to_lowercase();
            let value = parts[1];

            match keyword.as_str() {
                "host" => {
                    if let Some(host) = current_host.take() {
                        hosts.insert(host.name.clone(), host);
                    }

                    current_host = Some(HostConfig {
                        name: value.to_string(),
                        hostname: value.to_string(),
                        user: None,
                        port: 22,
                        identity_file: None,
                    });
                }
                "hostname" => {
                    if let Some(ref mut host) = current_host {
                        host.hostname = value.to_string();
                    }
                }
                "user" => {
                    if let Some(ref mut host) = current_host {
                        host.user = Some(value.to_string());
                    }
                }
                "port" => {
                    if let Some(ref mut host) = current_host {
                        if let Ok(port) = value.parse::<u16>() {
                            host.port = port;
                        }
                    }
                }
                "identityfile" => {
                    if let Some(ref mut host) = current_host {
                        let expanded = if value.starts_with('~') {
                            value.replacen("~", &std::env::var("HOME").unwrap_or_default(), 1)
                        } else {
                            value.to_string()
                        };
                        host.identity_file = Some(PathBuf::from(expanded));
                    }
                }
                _ => {}
            }
        }

        if let Some(host) = current_host {
            hosts.insert(host.name.clone(), host);
        }

        info!("Parsed {} hosts from SSH config", hosts.len());
        for (name, host) in hosts.iter() {
            debug!(
                "Host: {} -> {}@{}:{}",
                name,
                host.user.as_deref().unwrap_or("default"),
                host.hostname,
                host.port
            );
        }

        Ok(())
    }

    pub async fn connect(
        &self,
        host: &str,
        user: Option<&str>,
        port: Option<u16>,
    ) -> Result<SshSession> {
        let host_config = self.get_host_config(host).await;

        let (hostname, port, username, identity_file) = match host_config {
            Some(config) => {
                let hostname = config.hostname;
                let port = port.unwrap_or(config.port);
                let username = user
                    .or(config.user.as_deref())
                    .ok_or_else(|| anyhow::anyhow!("No user specified for host '{}'", host))?;
                (hostname, port, username.to_string(), config.identity_file)
            }
            None => {
                let hostname = host.to_string();
                let port = port.unwrap_or(22);
                let username =
                    user.ok_or_else(|| anyhow::anyhow!("No user specified for host '{}'", host))?;
                (hostname, port, username.to_string(), None)
            }
        };

        info!("Connecting to {}@{}:{}", username, hostname, port);
        SshSession::connect(&hostname, port, &username, identity_file.as_ref()).await
    }
}

/// SSH session with async output reading support
pub struct SshSession {
    session: Arc<Mutex<Option<russh::client::Handle<ClientHandler>>>>,
    channel: Arc<Mutex<russh::Channel<russh::client::Msg>>>,
    output_rx: Mutex<mpsc::Receiver<Result<Vec<u8>, String>>>,
    reader_task: Option<tokio::task::JoinHandle<()>>,
}

struct ClientHandler;

#[async_trait::async_trait]
impl russh::client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let home = std::env::var("HOME").unwrap_or_default();
        let known_hosts_path = format!("{}/.ssh/known_hosts", home);

        if let Ok(known_hosts) = std::fs::read_to_string(&known_hosts_path) {
            for line in known_hosts.lines() {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(key_part) = line.split_whitespace().nth(2) {
                    if let Ok(known_key) = russh_keys::parse_public_key_base64(key_part) {
                        if known_key == *server_public_key {
                            debug!("Server key verified from known_hosts");
                            return Ok(true);
                        }
                    }
                }
            }
        }

        warn!("Server key not found in known_hosts - accepting anyway");
        warn!(
            "Server key fingerprint: {}",
            server_public_key.fingerprint()
        );
        Ok(true)
    }
}

impl SshSession {
    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        identity_file: Option<&PathBuf>,
    ) -> Result<Self> {
        let config = Arc::new(russh::client::Config::default());
        let handler = ClientHandler;

        let mut session = russh::client::connect(config, (host, port), handler).await?;

        if let Some(key_path) = identity_file {
            let key_pair = load_secret_key(key_path, None)?;
            let auth_res = session
                .authenticate_publickey(user.to_string(), Arc::new(key_pair))
                .await?;
            if !auth_res {
                return Err(anyhow::anyhow!(
                    "Public key authentication failed for {}",
                    host
                ));
            }
        } else {
            let home = std::env::var("HOME").unwrap_or_default();
            let default_keys = [
                format!("{}/.ssh/id_ed25519", home),
                format!("{}/.ssh/id_rsa", home),
            ];

            let mut authenticated = false;
            for key_path in &default_keys {
                if std::path::Path::new(key_path).exists() {
                    match load_secret_key(&PathBuf::from(key_path), None) {
                        Ok(key_pair) => {
                            match session
                                .authenticate_publickey(user.to_string(), Arc::new(key_pair))
                                .await
                            {
                                Ok(true) => {
                                    authenticated = true;
                                    info!("Authenticated with key: {}", key_path);
                                    break;
                                }
                                _ => continue,
                            }
                        }
                        Err(e) => {
                            debug!("Failed to load key {}: {}", key_path, e);
                            continue;
                        }
                    }
                }
            }

            if !authenticated {
                return Err(anyhow::anyhow!(
                    "No valid SSH key found for {}. Password authentication not supported.",
                    host
                ));
            }
        }

        let channel = session.channel_open_session().await?;
        let (output_tx, output_rx) = mpsc::channel(64);

        // Start background reader task
        let ch = Arc::new(Mutex::new(channel));
        let ch_clone = ch.clone();
        let reader_task = tokio::spawn(async move {
            loop {
                let mut guard = ch_clone.lock().await;
                match tokio::time::timeout(std::time::Duration::from_millis(50), guard.wait()).await
                {
                    Ok(Some(msg)) => match msg {
                        russh::ChannelMsg::Data { data } => {
                            let bytes = data.as_ref().to_vec();
                            if !bytes.is_empty() {
                                if output_tx.send(Ok(bytes)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        russh::ChannelMsg::ExtendedData { data, ext: _ } => {
                            let bytes = data.as_ref().to_vec();
                            if !bytes.is_empty() {
                                if output_tx.send(Ok(bytes)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        russh::ChannelMsg::Eof | russh::ChannelMsg::Close => {
                            let _ = output_tx.send(Err("EOF".to_string())).await;
                            break;
                        }
                        _ => {}
                    },
                    Ok(None) => break,
                    Err(_) => {
                        drop(guard);
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
            }
            debug!("SSH output reader task stopped");
        });

        Ok(Self {
            session: Arc::new(Mutex::new(Some(session))),
            channel: ch,
            output_rx: Mutex::new(output_rx),
            reader_task: Some(reader_task),
        })
    }

    pub async fn request_pty(&mut self, term: &str, cols: u32, rows: u32) -> Result<()> {
        let channel = self.channel.lock().await;
        channel
            .request_pty(true, term, cols, rows, 0, 0, &[])
            .await?;
        Ok(())
    }

    pub async fn start_shell(&mut self) -> Result<()> {
        let channel = self.channel.lock().await;
        channel.request_shell(true).await?;
        Ok(())
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        let channel = self.channel.lock().await;
        channel.data(data).await?;
        Ok(())
    }

    pub async fn resize(&mut self, cols: u32, rows: u32) -> Result<()> {
        let channel = self.channel.lock().await;
        channel.window_change(cols, rows, 0, 0).await?;
        debug!("Terminal resized to {}x{}", cols, rows);
        Ok(())
    }

    /// Try to get output without blocking
    pub fn try_get_output(&self) -> Option<Vec<u8>> {
        // Non-blocking check using try_recv on the channel
        // This requires the receiver to be in a Mutex
        let mut rx = self.output_rx.try_lock().ok()?;
        match rx.try_recv() {
            Ok(Ok(data)) => Some(data),
            _ => None,
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        // Abort the reader task first
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }

        // Close the channel
        let channel = self.channel.lock().await;
        channel.close().await?;

        // Disconnect the session
        let mut session_guard = self.session.lock().await;
        if let Some(session) = session_guard.take() {
            drop(session);
        }

        debug!("SSH session closed");
        Ok(())
    }
}

fn load_secret_key(path: &PathBuf, passphrase: Option<&str>) -> Result<key::KeyPair> {
    let content = std::fs::read_to_string(path)?;
    if let Some(pass) = passphrase {
        russh_keys::decode_secret_key(&content, Some(pass))
    } else {
        russh_keys::decode_secret_key(&content, None)
    }
    .map_err(|e| anyhow::anyhow!("Failed to decode secret key: {:?}", e))
}

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use anyhow::Result;

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
    
    pub async fn list_hosts(&self) -> Result<Vec<String>> {
        let hosts = self.hosts.lock().await;
        Ok(hosts.keys().cloned().collect())
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
            debug!("Host: {} -> {}@{}:{}", 
                name, 
                host.user.as_deref().unwrap_or("default"),
                host.hostname,
                host.port
            );
        }
        
        Ok(())
    }
    
    pub async fn connect(&self, host: &str, user: Option<&str>, port: Option<u16>) -> Result<SshSession> {
        // First, try to get host from SSH config
        let host_config = self.get_host_config(host).await;
        
        let (hostname, port, username, identity_file) = match host_config {
            Some(config) => {
                let hostname = config.hostname;
                let port = port.unwrap_or(config.port);
                let username = user.or(config.user.as_deref())
                    .ok_or_else(|| anyhow::anyhow!("No user specified for host '{}'", host))?;
                (hostname, port, username.to_string(), config.identity_file)
            }
            None => {
                // Host not in config, treat host as hostname
                let hostname = host.to_string();
                let port = port.unwrap_or(22);
                let username = user.ok_or_else(|| anyhow::anyhow!("No user specified for host '{}'", host))?;
                (hostname, port, username.to_string(), None)
            }
        };
        
        info!("Connecting to {}@{}:{}", username, hostname, port);
        
        SshSession::connect(&hostname, port, &username, identity_file.as_ref()).await
    }
}

// SSH session implementation
pub struct SshSession {
    session: russh::client::Handle<ClientHandler>,
    channel: russh::Channel<russh::ChannelMsg>,
}

struct ClientHandler;

#[async_trait::async_trait]
impl russh::client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all keys - in production, check against known_hosts
        // TODO: Implement proper host key verification
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
        
        let mut session = russh::client::connect(
            config,
            (host, port),
            handler,
        ).await?;

        // Authenticate with key
        if let Some(key_path) = identity_file {
            let key_pair = load_secret_key(key_path, None)?;
            let auth_res = session.authenticate_publickey(user.to_string(), Arc::new(key_pair)).await?;
            if !auth_res {
                return Err(anyhow::anyhow!("Public key authentication failed for {}", host));
            }
        } else {
            // Try default key paths
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
                            match session.authenticate_publickey(user.to_string(), Arc::new(key_pair)).await {
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
                    "No valid SSH key found for {}. Password authentication not supported. \
                     Please provide identity file in SSH config or use default keys (id_ed25519, id_rsa).",
                    host
                ));
            }
        }

        // Open channel
        let channel = session.channel_open_session().await?;

        Ok(Self {
            session,
            channel,
        })
    }

    pub async fn request_pty(&mut self, term: &str, cols: u32, rows: u32) -> Result<()> {
        self.channel.request_pty(true, term, cols, rows, 0, 0, &[]).await?;
        Ok(())
    }

    pub async fn start_shell(&mut self) -> Result<()> {
        self.channel.request_shell(true).await?;
        Ok(())
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.channel.data(data).await?;
        Ok(())
    }

    pub async fn read_output(&mut self) -> Result<Option<Vec<u8>>> {
        // Non-blocking read from channel
        // russh uses async, so we need to handle the channel messages
        
        use tokio::time::{timeout, Duration};
        
        // Try to read with a small timeout to avoid blocking
        match timeout(Duration::from_millis(10), self.channel.wait()).await {
            Ok(Some(msg)) => {
                match msg {
                    russh::ChannelMsg::Data { data } => {
                        let bytes = data.as_ref().to_vec();
                        if !bytes.is_empty() {
                            return Ok(Some(bytes));
                        }
                    }
                    russh::ChannelMsg::ExtendedData { data, ext } => {
                        // stderr (ext == 1)
                        let bytes = data.as_ref().to_vec();
                        if !bytes.is_empty() {
                            return Ok(Some(bytes));
                        }
                    }
                    russh::ChannelMsg::Eof => {
                        return Ok(None);
                    }
                    _ => {}
                }
            }
            Ok(None) => {
                // Channel closed
                return Ok(None);
            }
            Err(_) => {
                // Timeout, no data available
            }
        }
        
        Ok(None)
    }

    pub async fn close(&mut self) -> Result<()> {
        self.channel.close().await?;
        Ok(())
    }
}

// Load SSH private key
fn load_secret_key(path: &PathBuf, passphrase: Option<&str>) -> Result<russh::keys::key::KeyPair> {
    let content = std::fs::read_to_string(path)?;
    
    if let Some(pass) = passphrase {
        russh::keys::decode_secret_key(&content, Some(pass.as_bytes()))
    } else {
        russh::keys::decode_secret_key(&content, None)
    }.map_err(|e| anyhow::anyhow!("Failed to decode secret key: {:?}", e))
}

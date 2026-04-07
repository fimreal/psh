use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub ssh_config_path: PathBuf,
    pub audit_log_path: PathBuf,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub auto_generate_certs: bool,
    pub jwt_secret: Option<String>,
    pub jwt_expire: u64,
    pub password: String,
}

#[derive(Debug, Deserialize)]
struct EnvConfig {
    #[serde(default = "default_host")]
    psh_host: String,
    #[serde(default = "default_port")]
    psh_port: u16,
    #[serde(default = "default_ssh_config")]
    psh_ssh_config: PathBuf,
    #[serde(default = "default_audit_log")]
    psh_audit_log: PathBuf,
    psh_tls_cert: Option<PathBuf>,
    psh_tls_key: Option<PathBuf>,
    #[serde(default = "default_auto_certs")]
    psh_auto_certs: bool,
    psh_jwt_secret: Option<String>,
    #[serde(default = "default_jwt_expire")]
    psh_jwt_expire: u64,
    psh_password: String,
}

fn default_host() -> String { "0.0.0.0".to_string() }
fn default_port() -> u16 { 8443 }
fn default_ssh_config() -> PathBuf { PathBuf::from("/root/.ssh/config") }
fn default_audit_log() -> PathBuf { PathBuf::from("/var/log/psh/audit.jsonl") }
fn default_auto_certs() -> bool { true }
fn default_jwt_expire() -> u64 { 86400 }

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let env_cfg: EnvConfig = envy::from_env()
            .map_err(|e| anyhow::anyhow!("Failed to parse environment variables: {}", e))?;

        Ok(Self {
            host: env_cfg.psh_host,
            port: env_cfg.psh_port,
            ssh_config_path: env_cfg.psh_ssh_config,
            audit_log_path: env_cfg.psh_audit_log,
            tls_cert_path: env_cfg.psh_tls_cert,
            tls_key_path: env_cfg.psh_tls_key,
            auto_generate_certs: env_cfg.psh_auto_certs,
            jwt_secret: env_cfg.psh_jwt_secret,
            jwt_expire: env_cfg.psh_jwt_expire,
            password: env_cfg.psh_password,
        })
    }
}

pub async fn load_tls_config(config: &Config) -> anyhow::Result<Option<axum_server::tls_rustls::RustlsConfig>> {
    use axum_server::tls_rustls::RustlsConfig;
    use std::path::Path;

    // If explicit cert/key paths provided, use them
    if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) {
        if Path::new(cert_path).exists() && Path::new(key_path).exists() {
            tracing::info!("Loading TLS certificates from {:?} and {:?}", cert_path, key_path);
            let config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
            return Ok(Some(config));
        } else {
            tracing::warn!("TLS cert/key paths provided but files not found");
        }
    }

    // Auto-generate self-signed certs if enabled
    if config.auto_generate_certs {
        tracing::info!("Generating self-signed TLS certificates");
        let (cert_pem, key_pem) = generate_self_signed_cert()?;
        let config = RustlsConfig::from_pem(
            cert_pem.into_bytes(),
            key_pem.into_bytes()
        ).await?;
        return Ok(Some(config));
    }

    // No TLS
    tracing::warn!("TLS not configured - running in HTTP mode (not recommended)");
    Ok(None)
}

fn generate_self_signed_cert() -> anyhow::Result<(String, String)> {
    use rcgen::generate_simple_self_signed;

    let subject_alt_names = vec![
        "localhost".to_string(),
        "psh".to_string(),
        "psh.local".to_string(),
    ];

    let cert = generate_simple_self_signed(subject_alt_names)
        .map_err(|e| anyhow::anyhow!("Failed to generate self-signed certificate: {}", e))?;

    let cert_pem = cert.serialize_pem()
        .map_err(|e| anyhow::anyhow!("Failed to serialize certificate: {}", e))?;
    let key_pem = cert.serialize_private_key_pem();

    Ok((cert_pem, key_pem))
}

use clap::Parser;
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

#[derive(Debug, Parser)]
#[command(name = "psh")]
#[command(about = "WebSSH Proxy Server", long_about = None)]
pub struct Args {
    /// Host address to bind to
    #[arg(short = 'H', long, env = "PSH_HOST", default_value = "0.0.0.0")]
    pub host: String,

    /// Port to listen on
    #[arg(short, long, env = "PSH_PORT", default_value = "8443")]
    pub port: u16,

    /// Path to SSH config file
    #[arg(
        short = 's',
        long,
        env = "PSH_SSH_CONFIG",
        default_value = "~/.ssh/config"
    )]
    pub ssh_config: PathBuf,

    /// Path to audit log file
    #[arg(
        short = 'a',
        long,
        env = "PSH_AUDIT_LOG",
        default_value = "~/.local/share/psh/audit.jsonl"
    )]
    pub audit_log: PathBuf,

    /// Path to TLS certificate file
    #[arg(long, env = "PSH_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// Path to TLS private key file
    #[arg(long, env = "PSH_TLS_KEY")]
    pub tls_key: Option<PathBuf>,

    /// Auto-generate self-signed TLS certificates
    #[arg(long, env = "PSH_AUTO_CERTS", default_value = "true")]
    pub auto_certs: bool,

    /// JWT secret key (auto-generated if not provided)
    #[arg(long, env = "PSH_JWT_SECRET")]
    pub jwt_secret: Option<String>,

    /// JWT token expiration time in seconds
    #[arg(long, env = "PSH_JWT_EXPIRE", default_value = "86400")]
    pub jwt_expire: u64,

    /// Password for authentication (required)
    #[arg(short = 'P', long, env = "PSH_PASSWORD")]
    pub password: String,
}

impl Config {
    pub fn from_args() -> anyhow::Result<Self> {
        let args = Args::parse();

        Ok(Self {
            host: args.host,
            port: args.port,
            ssh_config_path: expand_tilde(args.ssh_config),
            audit_log_path: expand_tilde(args.audit_log),
            tls_cert_path: args.tls_cert.map(expand_tilde),
            tls_key_path: args.tls_key.map(expand_tilde),
            auto_generate_certs: args.auto_certs,
            jwt_secret: args.jwt_secret,
            jwt_expire: args.jwt_expire,
            password: args.password,
        })
    }
}

fn expand_tilde(path: PathBuf) -> PathBuf {
    if path.starts_with("~") {
        if let Some(home) = dirs::home_dir() {
            return home.join(path.strip_prefix("~").unwrap());
        }
    }
    path
}

pub async fn load_tls_config(
    config: &Config,
) -> anyhow::Result<Option<axum_server::tls_rustls::RustlsConfig>> {
    use axum_server::tls_rustls::RustlsConfig;
    use std::path::Path;

    // If explicit cert/key paths provided, use them
    if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) {
        if Path::new(cert_path).exists() && Path::new(key_path).exists() {
            tracing::info!(
                "Loading TLS certificates from {:?} and {:?}",
                cert_path,
                key_path
            );
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
        let config = RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes()).await?;
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
        .map_err(|e| anyhow::anyhow!("Failed to generate self-signed certificate: {e}"))?;

    let cert_pem = cert
        .serialize_pem()
        .map_err(|e| anyhow::anyhow!("Failed to serialize certificate: {e}"))?;
    let key_pem = cert.serialize_private_key_pem();

    Ok((cert_pem, key_pem))
}

use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State, WebSocketUpgrade},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use axum::extract::ws::{Message, WebSocket};
use std::sync::Arc;
use std::net::SocketAddr;
// // use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

mod config;
mod ssh;
mod audit;
mod auth;

use config::Config;
use ssh::{SshManager, SshSession};
use audit::AuditLogger;
use auth::AuthService;

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    ssh_manager: Arc<SshManager>,
    audit: Arc<AuditLogger>,
    auth: Arc<AuthService>,
}

#[derive(Debug, serde::Deserialize)]
struct WsQuery {
    token: Option<String>,
    host: Option<String>,
    user: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, serde::Serialize)]
struct ConnectResponse {
    session_id: String,
    status: String,
}

#[derive(Debug, serde::Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, serde::Serialize)]
struct HostInfo {
    name: String,
    hostname: String,
    user: Option<String>,
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .with_target(true)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();

    info!("Starting psh (proxy shell) - WebSSH server");

    // Load configuration
    let config = Arc::new(Config::from_env()?);
    info!("Configuration loaded: host={}, port={}", config.host, config.port);

    // Initialize auth service
    if config.password.is_empty() {
        anyhow::bail!("PSH_PASSWORD environment variable is required");
    }
    let auth = Arc::new(AuthService::new(
        config.jwt_secret.clone(),
        config.jwt_expire,
        config.password.clone(),
    ));
    info!("Auth service initialized");

    // Initialize audit logger
    let audit = Arc::new(AuditLogger::new(&config.audit_log_path).await?);
    info!("Audit logger initialized: {:?}", config.audit_log_path);

    // Initialize SSH manager
    let ssh_manager = Arc::new(SshManager::new(&config.ssh_config_path).await?);
    info!("SSH manager initialized: {:?}", config.ssh_config_path);

    // Create app state
    let state = AppState {
        config: config.clone(),
        ssh_manager,
        audit,
        auth,
    };

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/", get(index_handler))
        .route("/api/auth/login", post(login_handler));

    // Protected routes (auth required)
    let protected_routes = Router::new()
        .route("/ws/terminal", get(terminal_ws_handler))
        .route("/api/hosts", get(list_hosts_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Static files
    let static_routes = Router::new()
        .route("/static/*path", get(static_handler));

    // Combine all routes
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(static_routes)
        .with_state(state);

    // Configure TLS
    let tls_config = config::load_tls_config(&config).await?;

    let addr = format!("{}:{}", config.host, config.port);
    info!("Starting HTTPS server on {}", addr);

    // Start server
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let socket_addr: std::net::SocketAddr = listener.local_addr()?;
    
    if let Some(tls_config) = tls_config {
        info!("TLS enabled - using HTTPS");
        axum_server::tls_rustls::bind_rustls(socket_addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        warn!("TLS not configured - using HTTP (not recommended for production)");
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    }

    Ok(())
}

// Auth middleware
async fn auth_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check for token in Authorization header or query params
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| {
            req.uri()
                .query()
                .and_then(|q| {
                    urlencoding_decode(q)
                        .find_map(|(k, v)| if k == "token" { Some(v.to_string()) } else { None })
                })
        });

    match token {
        Some(ref token) => {
            match state.auth.validate_token(token) {
                Ok(_claims) => Ok(next.run(req).await),
                Err(e) => {
                    warn!("Invalid token: {}", e);
                    Err(StatusCode::UNAUTHORIZED)
                }
            }
        }
        None => {
            warn!("No token provided");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

// Simple URL query string decoder
fn urlencoding_decode(s: &str) -> impl Iterator<Item = (&str, &str)> {
    s.split('&').filter_map(|pair| {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?;
        let value = parts.next().unwrap_or("");
        Some((key, value))
    })
}

// Route handlers
async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn static_handler(axum::extract::Path(path): axum::extract::Path<String>) -> impl IntoResponse {
    let mime_type = match path.rsplit('.').next() {
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("html") => "text/html",
        _ => "application/octet-stream",
    };
    
    let file_path = format!("static/{}", path);
    match tokio::fs::read(&file_path).await {
        Ok(content) => (
            [(axum::http::header::CONTENT_TYPE, mime_type)],
            content,
        ).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Debug, serde::Deserialize)]
struct LoginBody {
    password: String,
}

async fn login_handler(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if !state.auth.verify_password(&body.password) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid password".to_string(),
            }),
        ));
    }

    match state.auth.generate_token() {
        Ok(token) => {
            let response = serde_json::json!({
                "token": token,
                "expires_in": state.config.jwt_expire,
            });
            Ok(Json(response))
        }
        Err(e) => {
            error!("Failed to generate token: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to generate token".to_string(),
                }),
            ))
        }
    }
}

async fn list_hosts_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<HostInfo>>, (StatusCode, Json<ErrorResponse>)> {
    match state.ssh_manager.list_hosts_detailed().await {
        Ok(hosts) => Ok(Json(hosts.into_iter().map(|h| HostInfo {
            name: h.name,
            hostname: h.hostname,
            user: h.user,
            port: h.port,
        }).collect())),
        Err(e) => {
            error!("Failed to list hosts: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to list hosts: {}", e),
                }),
            ))
        }
    }
}

async fn terminal_ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    // Validate token from query param (since WebSocket can't set headers)
    let token = match query.token {
        Some(t) => t,
        None => {
            return (StatusCode::UNAUTHORIZED, "Missing token").into_response();
        }
    };

    match state.auth.validate_token(&token) {
        Ok(_claims) => {
            let host = query.host.clone();
            let user = query.user.clone();
            let port = query.port;
            
            ws.on_upgrade(move |socket| {
                handle_terminal_socket(socket, state, host, user, port, addr)
            })
        }
        Err(e) => {
            warn!("Invalid token for WebSocket: {}", e);
            (StatusCode::UNAUTHORIZED, "Invalid token").into_response()
        }
    }
}

async fn handle_terminal_socket(
    mut socket: WebSocket,
    state: AppState,
    host: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    addr: SocketAddr,
) {
    let session_id = uuid::Uuid::new_v4().to_string();
    info!("New WebSocket session {} from {}", session_id, addr);

    // Wait for initial connection message from client
    let mut ssh_session: Option<SshSession> = None;
    let mut current_host: Option<String> = None;
    let mut current_user: Option<String> = None;

    // Helper to send error message
    async fn send_error(socket: &mut WebSocket, msg: &str) {
        let _ = socket.send(Message::Text(serde_json::json!({
            "type": "error",
            "message": msg
        }).to_string())).await;
    }

    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            Message::Text(text) => {
                // Parse JSON message
                match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(json) => {
                        let msg_type = json.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        
                        match msg_type {
                            "connect" => {
                                // Connection request
                                let target_host = json.get("host")
                                    .and_then(|h| h.as_str())
                                    .or(host.as_deref());
                                let target_user = json.get("user")
                                    .and_then(|u| u.as_str())
                                    .or(user.as_deref());
                                let target_port = json.get("port")
                                    .and_then(|p| p.as_u64())
                                    .map(|p| p as u16)
                                    .or(port);

                                match target_host {
                                    Some(h) => {
                                        match state.ssh_manager.connect(h, target_user, target_port).await {
                                            Ok(mut session) => {
                                                current_host = Some(h.to_string());
                                                current_user = target_user.map(|s| s.to_string());
                                                
                                                // Request PTY and start shell
                                                if let Err(e) = session.request_pty("xterm-256color", 80, 24).await {
                                                    error!("Failed to request PTY: {}", e);
                                                    send_error(&mut socket, &format!("Failed to request PTY: {}", e)).await;
                                                    continue;
                                                }
                                                if let Err(e) = session.start_shell().await {
                                                    error!("Failed to start shell: {}", e);
                                                    send_error(&mut socket, &format!("Failed to start shell: {}", e)).await;
                                                    continue;
                                                }

                                                ssh_session = Some(session);
                                                
                                                // Log connection
                                                let _ = state.audit.log_connection(
                                                    &session_id,
                                                    h,
                                                    target_user,
                                                ).await;

                                                // Send connected message
                                                let _ = socket.send(Message::Text(serde_json::json!({
                                                    "type": "connected",
                                                    "session_id": session_id,
                                                    "host": h,
                                                    "user": target_user
                                                }).to_string())).await;
                                                
                                                info!("SSH connection established: {}@{}", 
                                                    target_user.unwrap_or("default"), h);
                                            }
                                            Err(e) => {
                                                error!("Failed to connect to {}: {}", h, e);
                                                send_error(&mut socket, &format!("Connection failed: {}", e)).await;
                                            }
                                        }
                                    }
                                    None => {
                                        send_error(&mut socket, "No host specified").await;
                                    }
                                }
                            }
                            "input" => {
                                // User input to SSH session
                                if let Some(ref mut session) = ssh_session {
                                    if let Some(data) = json.get("data").and_then(|d| d.as_str()) {
                                        if let Err(e) = session.write(data.as_bytes()).await {
                                            error!("Failed to write to SSH session: {}", e);
                                        }
                                    }
                                }
                            }
                            "resize" => {
                                // Terminal resize
                                if let Some(ref mut session) = ssh_session {
                                    let cols = json.get("cols").and_then(|c| c.as_u64()).unwrap_or(80) as u32;
                                    let rows = json.get("rows").and_then(|r| r.as_u64()).unwrap_or(24) as u32;
                                    
                                    // Note: russh doesn't support terminal resize directly
                                    // This would require channel resize which is not in the current API
                                    debug!("Terminal resize requested: {}x{}", cols, rows);
                                }
                            }
                            _ => {
                                debug!("Unknown message type: {}", msg_type);
                            }
                        }
                    }
                    Err(_e) => {
                        // Not JSON, treat as raw input (backward compatibility)
                        if let Some(ref mut session) = ssh_session {
                            if let Err(e) = session.write(text.as_bytes()).await {
                                error!("Failed to write to SSH session: {}", e);
                            }
                        }
                    }
                }
            }
            Message::Binary(data) => {
                // Binary input to SSH session
                if let Some(ref mut session) = ssh_session {
                    if let Err(e) = session.write(&data).await {
                        error!("Failed to write binary to SSH session: {}", e);
                    }
                }
            }
            Message::Ping(data) => {
                let _ = socket.send(Message::Pong(data)).await;
            }
            Message::Pong(_) => {}
            Message::Close(_) => {
                info!("WebSocket session {} closed by client", session_id);
                break;
            }
        }

        // Read output from SSH session if connected
        if let Some(ref mut session) = ssh_session {
            // Try to read output (non-blocking)
            match session.read_output().await {
                Ok(Some(output)) => {
                    let output_b64 = base64_engine::encode(&output);
                    if let Err(e) = socket.send(Message::Text(serde_json::json!({
                        "type": "output",
                        "data": output_b64
                    }).to_string())).await {
                        error!("Failed to send output: {}", e);
                        break;
                    }
                }
                Ok(None) => {
                    // No data available, continue
                }
                Err(e) => {
                    error!("Failed to read from SSH session: {}", e);
                    send_error(&mut socket, &format!("SSH read error: {}", e)).await;
                    break;
                }
            }
        }
    }

    // Cleanup
    if let Some(host) = &current_host {
        let _ = state.audit.log_disconnection(&session_id, host).await;
    }
    
    if let Some(mut session) = ssh_session {
        let _ = session.close().await;
    }

    info!("WebSocket session {} ended", session_id);
}

// Base64 encoder for output
mod base64_engine {
    use base64::{engine::general_purpose::STANDARD, Engine};
    
    pub fn encode(data: &[u8]) -> String {
        STANDARD.encode(data)
    }
}

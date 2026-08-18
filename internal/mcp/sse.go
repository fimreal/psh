package mcp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/fimreal/goutils/ezap"
)

const (
	// sseKeepaliveInterval is how often a comment line is written to idle SSE
	// streams so proxies do not close them and dead peers are detected.
	sseKeepaliveInterval = 15 * time.Second

	// maxMessageSize caps the size of a single inbound JSON-RPC message.
	maxMessageSize = 1 << 20 // 1 MiB

	// sseOutboundBuffer is the per-connection outbound response queue.
	sseOutboundBuffer = 256

	// sseConnIDBytes is the entropy of a connection identifier.
	sseConnIDBytes = 16
)

// authKey is one accepted bearer token with its audit identifier.
type authKey struct {
	token      string
	identifier string
}

// SSEServer exposes a Server over HTTP using the MCP "HTTP with SSE"
// transport (spec revision 2024-11-05):
//
//   - GET  /sse       opens the event stream; the first event ("endpoint")
//     carries the per-connection message endpoint URL.
//   - POST /messages  delivers JSON-RPC requests for a connection; responses
//     are streamed back over that connection's SSE channel.
//   - GET  /healthz   liveness probe for docker/systemd supervision.
//
// Remote mode is fail-closed: at least one bearer token must be configured
// (PSH_MCP_API_KEYS) or NewSSEServer refuses to start. Every request must
// present a valid "Authorization: Bearer <token>" header, and a connection
// can only be driven by the token that created it.
type SSEServer struct {
	server *Server
	keys   []authKey

	mu    sync.Mutex
	conns map[string]*sseConn

	httpSrv *http.Server
}

// sseConn tracks one established SSE client connection.
type sseConn struct {
	id       string
	clientID string // authenticated key identifier (rate limiting + audit)
	outbound chan json.RawMessage

	closeOnce sync.Once
	done      chan struct{}
}

// NewSSEServer wraps server with the SSE transport. keys maps bearer tokens
// to human-readable identifiers used for rate limiting and audit logging.
func NewSSEServer(server *Server, keys map[string]string) (*SSEServer, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("remote (sse) mode requires at least one API key (set PSH_MCP_API_KEYS)")
	}

	authKeys := make([]authKey, 0, len(keys))
	for token, identifier := range keys {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		authKeys = append(authKeys, authKey{token: token, identifier: identifier})
	}
	if len(authKeys) == 0 {
		return nil, fmt.Errorf("remote (sse) mode requires at least one non-empty API key")
	}

	return &SSEServer{
		server: server,
		keys:   authKeys,
		conns:  make(map[string]*sseConn),
	}, nil
}

// Handler returns the HTTP handler implementing the SSE transport. Exposed
// for tests and for embedding into a larger HTTP mux.
func (t *SSEServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", t.handleSSE)
	mux.HandleFunc("/messages", t.handleMessages)
	mux.HandleFunc("/healthz", t.handleHealthz)
	return mux
}

// Serve accepts connections on ln until the listener is closed or Shutdown
// is called. The caller is responsible for wrapping ln with TLS if needed.
func (t *SSEServer) Serve(ln net.Listener) error {
	t.httpSrv = &http.Server{
		Handler:           t.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No global Read/Write timeouts: SSE streams are long-lived and
		// tool calls (SSH exec) may legitimately run for minutes.
	}
	err := t.httpSrv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown gracefully stops the HTTP server and tears down all SSE
// connections.
func (t *SSEServer) Shutdown(ctx context.Context) error {
	t.mu.Lock()
	for _, conn := range t.conns {
		conn.closeOnce.Do(func() { close(conn.done) })
	}
	t.mu.Unlock()

	if t.httpSrv == nil {
		return nil
	}
	return t.httpSrv.Shutdown(ctx)
}

// --- HTTP handlers ---

func (t *SSEServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","server":"psh-mcp"}`))
}

func (t *SSEServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	clientID, ok := t.authenticate(w, r)
	if !ok {
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	id, err := newConnID()
	if err != nil {
		http.Error(w, "failed to allocate connection", http.StatusInternalServerError)
		return
	}

	conn := &sseConn{
		id:       id,
		clientID: clientID,
		outbound: make(chan json.RawMessage, sseOutboundBuffer),
		done:     make(chan struct{}),
	}
	t.mu.Lock()
	t.conns[id] = conn
	t.mu.Unlock()
	defer t.removeConn(id)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // disable proxy buffering (nginx)
	w.WriteHeader(http.StatusOK)

	// Announce the message endpoint for this connection (MCP 2024-11-05).
	if _, err := fmt.Fprintf(w, "event: endpoint\ndata: /messages?sessionId=%s\n\n", id); err != nil {
		return
	}
	flusher.Flush()

	log.Infow("MCP SSE client connected", "connection", id, "client", clientID, "remote_addr", r.RemoteAddr)

	ticker := time.NewTicker(sseKeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			log.Infow("MCP SSE client disconnected", "connection", id, "client", clientID)
			return
		case <-conn.done:
			return
		case data := <-conn.outbound:
			if _, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (t *SSEServer) handleMessages(w http.ResponseWriter, r *http.Request) {
	clientID, ok := t.authenticate(w, r)
	if !ok {
		return
	}

	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed, use POST")
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	conn := t.getConn(sessionID)
	// A connection can only be driven by the token that established it.
	// Respond 404 (not 403) so other clients' session IDs are not revealed.
	if conn == nil || conn.clientID != clientID {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxMessageSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parse error: invalid JSON-RPC message")
		return
	}

	send := func(resp jsonRPCResponse) {
		data, err := json.Marshal(resp)
		if err != nil {
			log.Errorw("Failed to marshal MCP response", "error", err)
			return
		}
		select {
		case conn.outbound <- data:
		default:
			// The client stopped consuming its stream; drop the connection
			// instead of buffering responses without bound.
			log.Warnw("MCP SSE outbound buffer full, closing connection",
				"connection", conn.id, "client", conn.clientID)
			t.removeConn(conn.id)
		}
	}

	t.server.handleRequest(&req, clientID, send)

	w.WriteHeader(http.StatusAccepted)
}

// --- Connection registry ---

func (t *SSEServer) getConn(id string) *sseConn {
	if id == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conns[id]
}

func (t *SSEServer) removeConn(id string) {
	t.mu.Lock()
	conn, ok := t.conns[id]
	if ok {
		delete(t.conns, id)
	}
	t.mu.Unlock()

	if ok {
		conn.closeOnce.Do(func() { close(conn.done) })
	}
}

// ConnCount reports the number of active SSE connections (for monitoring).
func (t *SSEServer) ConnCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// --- Auth ---

// authenticate validates the Authorization header against the configured
// bearer tokens using constant-time comparison. On success it returns the
// key identifier; on failure it writes a 401 response and returns false.
func (t *SSEServer) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		writeAuthError(w, "missing or invalid Authorization header, expected: Bearer <token>")
		return "", false
	}

	for _, k := range t.keys {
		if subtle.ConstantTimeCompare([]byte(token), []byte(k.token)) == 1 {
			return k.identifier, true
		}
	}

	writeAuthError(w, "invalid API key")
	return "", false
}

// --- Helpers ---

func newConnID() (string, error) {
	buf := make([]byte, sseConnIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func writeAuthError(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSONError(w, http.StatusUnauthorized, message)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	data, _ := json.Marshal(map[string]string{"error": message})
	_, _ = w.Write(data)
}

package mcp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/audit"
)

var (
	// sseKeepaliveInterval is how often a comment line is written to idle SSE
	// streams so proxies do not close them and dead peers are detected.
	sseKeepaliveInterval = 15 * time.Second

	// sseWriteTimeout bounds a single write to an SSE stream. A client that
	// stops reading must not block the handler goroutine forever.
	sseWriteTimeout = 10 * time.Second

	// sseBodyReadTimeout bounds reading a POST /messages request body so a
	// slow-drip client cannot pin a goroutine indefinitely.
	sseBodyReadTimeout = 30 * time.Second
)

const (
	// maxMessageSize caps the size of a single inbound JSON-RPC message.
	maxMessageSize = 1 << 20 // 1 MiB

	// sseOutboundBuffer is the per-connection outbound response queue.
	sseOutboundBuffer = 256

	// sseConnIDBytes is the entropy of a connection identifier.
	sseConnIDBytes = 16

	// DefaultMaxConnections bounds concurrent SSE connections.
	DefaultMaxConnections = 100

	// maxInflightPerConn bounds concurrently executing JSON-RPC requests of
	// one connection so a single client cannot spawn unbounded goroutines.
	maxInflightPerConn = 8
)

// SSEOptions tunes the SSE transport. Zero values select defaults.
type SSEOptions struct {
	// MaxConnections caps concurrent SSE connections
	// (default DefaultMaxConnections).
	MaxConnections int

	// TrustProxyHeaders makes the endpoint URL honor X-Forwarded-Proto and
	// X-Forwarded-Host. Only enable this behind a trusted proxy that
	// overwrites these headers; otherwise clients could spoof them.
	TrustProxyHeaders bool

	// BasePath is the mount prefix of the SSE endpoints when the handler is
	// embedded into a larger HTTP mux (e.g. "/mcp" for the integrated web
	// server). It is prefixed to the /messages URL announced to clients so
	// their POSTs reach the mounted route. Empty means root-level mounting.
	BasePath string
}

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
//   - POST /messages  delivers JSON-RPC requests for a connection; the server
//     answers 202 immediately and streams responses back over the SSE channel
//     once they are ready (requests execute concurrently).
//   - GET  /healthz   liveness probe for docker/systemd supervision.
//
// Remote mode is fail-closed: at least one bearer token must be configured
// (PSH_MCP_API_KEYS) or NewSSEServer refuses to start. Every request must
// present a valid "Authorization: Bearer <token>" header, and a connection
// can only be driven by the exact token that created it.
type SSEServer struct {
	server *Server
	keys   []authKey

	maxConnections    int
	trustProxyHeaders bool
	basePath          string

	// dispatch serializes the start of request execution so POST /messages
	// can return 202 immediately while tools (SSH exec up to minutes) run
	// asynchronously. The dispatcher exits when closed is closed.
	dispatch chan dispatchJob
	closed   chan struct{}

	mu    sync.Mutex
	conns map[string]*sseConn

	shutdownOnce sync.Once

	httpSrv *http.Server
}

type dispatchJob struct {
	conn *sseConn
	req  jsonRPCRequest
	send sendFunc
}

// sseConn tracks one established SSE client connection.
type sseConn struct {
	id       string
	keyIdx   int    // index into SSEServer.keys: the exact token that opened it
	clientID string // authenticated key identifier (rate limiting + audit)
	outbound chan json.RawMessage
	inflight atomic.Int64

	closeOnce sync.Once
	done      chan struct{}
}

// NewSSEServer wraps server with the SSE transport. keys maps bearer tokens
// to human-readable identifiers used for rate limiting and audit logging.
// Identifiers must be non-empty and unique: they are the rate-limit keys and
// connection ownership is enforced by token identity, not identifier.
func NewSSEServer(server *Server, keys map[string]string, opts SSEOptions) (*SSEServer, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("remote (sse) mode requires at least one API key (set PSH_MCP_API_KEYS)")
	}

	authKeys := make([]authKey, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for token, identifier := range keys {
		token = strings.TrimSpace(token)
		identifier = strings.TrimSpace(identifier)
		if token == "" {
			continue
		}
		if identifier == "" {
			return nil, fmt.Errorf("API key identifier must not be empty")
		}
		if seen[identifier] {
			return nil, fmt.Errorf("duplicate API key identifier %q", identifier)
		}
		seen[identifier] = true
		authKeys = append(authKeys, authKey{token: token, identifier: identifier})
	}
	if len(authKeys) == 0 {
		return nil, fmt.Errorf("remote (sse) mode requires at least one non-empty API key")
	}

	maxConns := opts.MaxConnections
	if maxConns <= 0 {
		maxConns = DefaultMaxConnections
	}

	t := &SSEServer{
		server:            server,
		keys:              authKeys,
		maxConnections:    maxConns,
		trustProxyHeaders: opts.TrustProxyHeaders,
		basePath:          strings.TrimSuffix(opts.BasePath, "/"),
		// Sized so every connection can always hold up to maxInflightPerConn
		// queued-or-executing jobs; overflow beyond that sheds load via the
		// senders' default branch instead of growing memory.
		dispatch: make(chan dispatchJob, maxInflightPerConn*maxConns),
		closed:   make(chan struct{}),
		conns:    make(map[string]*sseConn),
	}
	t.httpSrv = &http.Server{
		Handler:           t.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No global Read/Write timeouts: SSE streams are long-lived and
		// tool calls (SSH exec) may legitimately run for minutes. Slow
		// clients are bounded per operation instead (sseWriteTimeout,
		// sseBodyReadTimeout).
	}

	// The dispatcher decouples POST /messages from request execution so the
	// transport can acknowledge immediately; it exits on Shutdown.
	go t.runDispatcher()

	return t, nil
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
	err := t.httpSrv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// SetTrustedProxyHeaders controls whether X-Forwarded-Proto/Host are honored
// when building the endpoint URL. Only enable behind a trusted proxy that
// overwrites these headers. Must be called before Serve.
func (t *SSEServer) SetTrustedProxyHeaders(v bool) {
	t.trustProxyHeaders = v
}

// Shutdown gracefully stops the HTTP server, the dispatcher and tears down
// all SSE connections. In-flight HTTP handlers are allowed to finish, but
// tool executions already handed to the dispatcher are NOT awaited: after
// Shutdown returns (or main exits) they may be interrupted mid-run, and
// clients holding a 202 may never receive a response — an accepted risk of
// the 202-acknowledged async protocol.
func (t *SSEServer) Shutdown(ctx context.Context) error {
	t.shutdownOnce.Do(func() { close(t.closed) })

	t.mu.Lock()
	for _, conn := range t.conns {
		conn.closeOnce.Do(func() { close(conn.done) })
	}
	t.mu.Unlock()

	err := t.httpSrv.Shutdown(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil // already shut down: keep Shutdown idempotent
	}
	return err
}

// runDispatcher starts execution of incoming JSON-RPC requests. It exits when
// the server shuts down; still-queued jobs are discarded (their connections
// are being torn down). Each job's inflight slot was already reserved by the
// POST handler; the slot is released here once execution finishes.
func (t *SSEServer) runDispatcher() {
	for {
		select {
		case job := <-t.dispatch:
			go func() {
				defer job.conn.inflight.Add(-1)
				t.server.handleRequest(&job.req, job.conn.clientID, job.send)
			}()
		case <-t.closed:
			return
		}
	}
}

// --- HTTP handlers ---

func (t *SSEServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","server":"psh-mcp"}`))
}

func (t *SSEServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed, use GET")
		return
	}

	keyIdx, clientID, ok := t.authenticate(w, r)
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
		keyIdx:   keyIdx,
		clientID: clientID,
		outbound: make(chan json.RawMessage, sseOutboundBuffer),
		done:     make(chan struct{}),
	}

	// Enforce the connection cap atomically with registration.
	t.mu.Lock()
	if len(t.conns) >= t.maxConnections {
		t.mu.Unlock()
		log.Warnw("MCP SSE connection limit reached", "limit", t.maxConnections, "client", clientID, "remote_addr", r.RemoteAddr)
		writeJSONError(w, http.StatusTooManyRequests, "connection limit reached")
		return
	}
	t.conns[id] = conn
	t.mu.Unlock()
	defer t.removeConn(id)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // disable proxy buffering (nginx)
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	// Announce the message endpoint for this connection (MCP 2024-11-05).
	// An absolute URL maximizes client compatibility.
	if _, err := fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", t.messageEndpointURL(r, id)); err != nil {
		return
	}
	flusher.Flush()

	log.Infow("MCP SSE client connected", "connection", id, "client", clientID, "remote_addr", r.RemoteAddr)

	// ResponseController sets per-write deadlines so a client that stops
	// reading cannot block this goroutine forever (nil-safe when the server
	// does not support deadlines, e.g. httptest).
	rc := http.NewResponseController(w)

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
			if err := writeEventWithDeadline(rc, w, "event: message\ndata: "+string(data)+"\n\n"); err != nil {
				log.Warnw("MCP SSE write failed, closing connection", "connection", id, "client", clientID, "error", err)
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if err := writeEventWithDeadline(rc, w, ": keepalive\n\n"); err != nil {
				log.Warnw("MCP SSE keepalive failed, closing connection", "connection", id, "client", clientID, "error", err)
				return
			}
			flusher.Flush()
		}
	}
}

func (t *SSEServer) handleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed, use POST")
		return
	}

	keyIdx, _, ok := t.authenticate(w, r)
	if !ok {
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	conn := t.getConn(sessionID)
	// A connection can only be driven by the exact token that established
	// it. Respond 404 (not 403) so other clients' session IDs are not
	// revealed.
	if conn == nil || conn.keyIdx != keyIdx {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}

	body, status, err := readBodyWithTimeout(w, r)
	if err != nil {
		writeJSONError(w, status, err.Error())
		return
	}

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parse error: invalid JSON-RPC message")
		return
	}

	// Reserve one outstanding-job slot atomically before enqueueing. The
	// counter covers queued AND executing jobs, so this is a hard per-
	// connection cap (no check-then-enqueue race), and a single connection
	// can never hog more than maxInflightPerConn entries of the global queue.
	if conn.inflight.Add(1) > maxInflightPerConn {
		conn.inflight.Add(-1)
		writeJSONError(w, http.StatusTooManyRequests, "too many pending requests for this connection")
		return
	}

	send := t.makeSend(conn)
	sent := true
	select {
	case t.dispatch <- dispatchJob{conn: conn, req: req, send: send}:
	case <-conn.done:
		writeJSONError(w, http.StatusNotFound, "session not found")
		sent = false
	case <-t.closed:
		writeJSONError(w, http.StatusServiceUnavailable, "server shutting down")
		sent = false
	default:
		// Dispatcher queue full: shed load instead of buffering without bound.
		writeJSONError(w, http.StatusServiceUnavailable, "server busy, retry later")
		sent = false
	}
	if !sent {
		conn.inflight.Add(-1)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

// writeEventWithDeadline writes one SSE frame with a fresh write deadline so
// a stalled reader cannot pin the streaming goroutine beyond sseWriteTimeout.
func writeEventWithDeadline(rc *http.ResponseController, w io.Writer, payload string) error {
	_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
	_, err := fmt.Fprint(w, payload)
	return err
}

// makeSend builds the response sink for a connection: responses are queued
// for the SSE stream; a stalled consumer (queue full) drops the connection
// rather than growing memory without bound. This branch is defense in depth:
// with the per-connection inflight cap the buffer should never fill, but if
// it ever does we fail closed.
func (t *SSEServer) makeSend(conn *sseConn) sendFunc {
	return func(resp jsonRPCResponse) {
		data, err := json.Marshal(resp)
		if err != nil {
			log.Errorw("Failed to marshal MCP response", "error", err)
			return
		}
		select {
		case <-conn.done:
			// Connection already torn down; discard the response.
		case conn.outbound <- data:
		default:
			log.Warnw("MCP SSE outbound buffer full, closing connection",
				"connection", conn.id, "client", conn.clientID)
			t.removeConn(conn.id)
			conn.closeOnce.Do(func() { close(conn.done) })
		}
	}
}

// readBodyWithTimeout reads the request body with both a size cap and a time
// cap so slow or oversized uploads cannot pin goroutines.
func readBodyWithTimeout(w http.ResponseWriter, r *http.Request) ([]byte, int, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxMessageSize)

	type readResult struct {
		data []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(r.Body)
		ch <- readResult{data: data, err: err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(res.err, &maxBytesErr) {
				return nil, http.StatusRequestEntityTooLarge,
					fmt.Errorf("request body exceeds limit of %d bytes", maxMessageSize)
			}
			return nil, http.StatusBadRequest, errors.New("failed to read request body")
		}
		return res.data, http.StatusOK, nil
	case <-time.After(sseBodyReadTimeout):
		return nil, http.StatusRequestTimeout, errors.New("request body read timed out")
	}
}

// messageEndpointURL builds the absolute message endpoint URL announced to
// the client. X-Forwarded-Proto/Host are only honored when explicitly enabled
// (SetTrustedProxyHeaders / SSEOptions.TrustProxyHeaders): blindly trusting
// them lets direct clients spoof where their own subsequent POSTs go.
func (t *SSEServer) messageEndpointURL(r *http.Request, sessionID string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if t.trustProxyHeaders {
		switch fp := r.Header.Get("X-Forwarded-Proto"); fp {
		case "https":
			scheme = "https"
		case "http":
			scheme = "http"
		}
		if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
			host = fh
		}
	}
	return fmt.Sprintf("%s://%s%s/messages?sessionId=%s", scheme, host, t.basePath, sessionID)
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

// MaxConnections reports the configured concurrent SSE connection cap.
func (t *SSEServer) MaxConnections() int {
	return t.maxConnections
}

// --- Auth ---

// authenticate validates the Authorization header against the configured
// bearer tokens using constant-time comparison. The auth scheme is
// case-insensitive per RFC 9110. On success it returns the key index and
// identifier; on failure it writes a 401 response, logs the attempt and
// returns false.
func (t *SSEServer) authenticate(w http.ResponseWriter, r *http.Request) (int, string, bool) {
	header := r.Header.Get("Authorization")
	token, ok := cutBearerToken(header)
	if !ok {
		t.logAuthFailure(r, "missing or invalid Authorization header")
		writeAuthError(w, "missing or invalid Authorization header, expected: Bearer <token>")
		return 0, "", false
	}

	for i, k := range t.keys {
		if subtle.ConstantTimeCompare([]byte(token), []byte(k.token)) == 1 {
			return i, k.identifier, true
		}
	}

	t.logAuthFailure(r, "invalid API key")
	writeAuthError(w, "invalid API key")
	return 0, "", false
}

// cutBearerToken extracts the token from an Authorization header, accepting
// the "bearer" scheme case-insensitively.
func cutBearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// logAuthFailure records a failed authentication attempt in the application
// log and the audit trail: brute-forcing tokens must not be invisible.
func (t *SSEServer) logAuthFailure(r *http.Request, reason string) {
	log.Warnw("MCP SSE authentication failed",
		"reason", reason,
		"remote_addr", r.RemoteAddr,
		"path", r.URL.Path,
	)
	if t.server.auditLogger != nil {
		_ = t.server.auditLogger.LogAPIEvent(audit.EventError, "", "", r.RemoteAddr, "mcp auth failed: "+reason)
	}
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
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	data, _ := json.Marshal(map[string]string{"error": message})
	_, _ = w.Write(data)
}

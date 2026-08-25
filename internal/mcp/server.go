package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/api"
	"github.com/fimreal/psh/internal/audit"
)

// Server implements a JSON-RPC 2.0 based MCP server over stdio.
type Server struct {
	sessionMgr     *api.SessionManager
	auditLogger    *audit.Logger
	ownsAudit      bool
	apiKeyID       string
	allowedHosts   map[string]bool
	limiter        *RateLimiter
	maxExecTimeout time.Duration
	mu             sync.Mutex
	writer         *bufio.Writer

	// preExec, when non-nil, is invoked by handleRequest before executing a
	// request. Test-only hook for deterministic async-dispatch regression
	// tests; must be set before the server starts serving.
	preExec func(req jsonRPCRequest)
}

// Config holds MCP server configuration.
type Config struct {
	SessionTimeout time.Duration
	SessionMaxLife time.Duration
	ExecTimeout    time.Duration
	AllowedHosts   []string
	AuditLogPath   string
	AuditLevel     string
	APIKeyID       string

	// Rate limiting
	RateLimit   int           // max tool calls per client per RateWindow (default: 10)
	RateWindow  time.Duration // sliding window for rate limiting (default: 1m)
	MaxSessions int           // max concurrent SSH sessions (default: 5, 0 = unlimited)

	// SharedAuditLogger, when set, reuses the main web server's audit logger
	// so webshell and MCP activity land in the same recent-events ring and
	// file. When nil, a standalone logger is created from AuditLogPath.
	SharedAuditLogger *audit.Logger
}

// Default rate limiting values.
const (
	DefaultRateLimit   = 10
	DefaultRateWindow  = time.Minute
	DefaultMaxSessions = 5

	// defaultMaxExecTimeout caps per-command execution time when no explicit
	// Config.ExecTimeout is provided.
	defaultMaxExecTimeout = 300 * time.Second
)

// NewServer creates a new MCP server.
func NewServer(cfg Config) (*Server, error) {
	auditLogger := cfg.SharedAuditLogger
	ownsAudit := false
	if auditLogger == nil {
		var err error
		auditLogger, err = audit.NewLogger(cfg.AuditLogPath, audit.Level(cfg.AuditLevel))
		if err != nil {
			return nil, fmt.Errorf("failed to create audit logger: %w", err)
		}
		ownsAudit = true
	}

	sessionMgr := api.NewSessionManager(cfg.SessionTimeout, cfg.SessionMaxLife)

	hostSet := make(map[string]bool, len(cfg.AllowedHosts))
	for _, h := range cfg.AllowedHosts {
		hostSet[strings.TrimSpace(h)] = true
	}

	// Apply rate limiting defaults.
	rateLimit := cfg.RateLimit
	if rateLimit <= 0 {
		rateLimit = DefaultRateLimit
	}
	rateWindow := cfg.RateWindow
	if rateWindow <= 0 {
		rateWindow = DefaultRateWindow
	}
	maxSessions := cfg.MaxSessions
	if maxSessions < 0 {
		maxSessions = 0
	} else if maxSessions == 0 {
		maxSessions = DefaultMaxSessions
	}

	limiter := NewRateLimiter(rateLimit, rateWindow, maxSessions)

	// Apply exec timeout default.
	maxExecTimeout := cfg.ExecTimeout
	if maxExecTimeout <= 0 {
		maxExecTimeout = defaultMaxExecTimeout
	}

	return &Server{
		sessionMgr:     sessionMgr,
		auditLogger:    auditLogger,
		ownsAudit:      ownsAudit,
		apiKeyID:       cfg.APIKeyID,
		allowedHosts:   hostSet,
		limiter:        limiter,
		maxExecTimeout: maxExecTimeout,
		writer:         bufio.NewWriter(os.Stdout),
	}, nil
}

// isHostAllowed checks whether the given host is in the allowed hosts whitelist.
// An empty whitelist means no hosts are allowed (fail-closed).
func (s *Server) isHostAllowed(host string) bool {
	if len(s.allowedHosts) == 0 {
		return false
	}
	return s.allowedHosts[host]
}

// --- JSON-RPC types ---

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// sendFunc delivers a JSON-RPC response to the requesting client. The stdio
// transport writes to stdout; the SSE transport pushes to a per-connection
// event stream. The client argument carried through handleRequest identifies
// the caller for rate limiting and audit logging.
type sendFunc func(resp jsonRPCResponse)

// --- MCP protocol types ---

type initializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    capabilities `json:"capabilities"`
	ServerInfo      serverInfo   `json:"serverInfo"`
}

type capabilities struct {
	Tools *toolsCapability `json:"tools,omitempty"`
}

type toolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema inputSchema `json:"inputSchema"`
}

type inputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
}

type property struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

type toolsListResult struct {
	Tools []tool `json:"tools"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type toolCallResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// --- Tool input types ---

type sshExecInput struct {
	Host    string `json:"host"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

type sshSessionCreateInput struct {
	Host string `json:"host"`
}

type sshSessionExecInput struct {
	SessionID string `json:"session_id"`
	Command   string `json:"command"`
	Timeout   int    `json:"timeout,omitempty"`
}

type sshSessionCloseInput struct {
	SessionID string `json:"session_id"`
}

// Run starts the MCP server reading from stdin and writing to stdout.
//
// A stdio MCP server has a single connected client (the process on the other
// end of the pipe), so every request shares the configured API key identity.
func (s *Server) Run() error {
	scanner := bufio.NewScanner(os.Stdin)
	// Allow large messages
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	send := s.stdioSend
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			sendError(send, nil, -32700, "Parse error")
			continue
		}

		s.handleRequest(&req, s.apiKeyID, send)
	}

	return scanner.Err()
}

// stdioSend delivers a JSON-RPC response to the single stdio client.
func (s *Server) stdioSend(resp jsonRPCResponse) {
	s.writeResponse(resp)
}

// Close cleans up server resources.
func (s *Server) Close() {
	s.sessionMgr.Close()
	if s.ownsAudit {
		// A shared logger is owned (and closed) by the main web server.
		s.auditLogger.Close()
	}
	if s.limiter != nil {
		s.limiter.Close()
	}
}

// handleRequest dispatches a single JSON-RPC request. client identifies the
// caller (rate limiting + audit) and send delivers responses back to it.
func (s *Server) handleRequest(req *jsonRPCRequest, client string, send sendFunc) {
	if s.preExec != nil {
		s.preExec(*req)
	}
	switch req.Method {
	case "initialize":
		s.handleInitialize(req, send)
	case "notifications/initialized":
		// No response needed for notifications
	case "tools/list":
		s.handleToolsList(req, send)
	case "tools/call":
		s.handleToolsCall(req, client, send)
	case "ping":
		sendResult(send, req.ID, map[string]interface{}{})
	default:
		sendError(send, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func (s *Server) handleInitialize(req *jsonRPCRequest, send sendFunc) {
	sendResult(send, req.ID, initializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities: capabilities{
			Tools: &toolsCapability{ListChanged: false},
		},
		ServerInfo: serverInfo{
			Name:    "psh-mcp",
			Version: "1.0.0",
		},
	})
}

func (s *Server) handleToolsList(req *jsonRPCRequest, send sendFunc) {
	tools := []tool{
		{
			Name:        "ssh_exec",
			Description: "Execute a command on a remote host (one-shot: auto create session, exec, close)",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]property{
					"host":    {Type: "string", Description: "SSH host to connect to (must be in allowed hosts)"},
					"command": {Type: "string", Description: "Command to execute"},
					"timeout": {Type: "integer", Description: "Command timeout in seconds (default: 30, max: 300)"},
				},
				Required: []string{"host", "command"},
			},
		},
		{
			Name:        "ssh_session_create",
			Description: "Create a persistent SSH session for multiple commands",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]property{
					"host": {Type: "string", Description: "SSH host to connect to (must be in allowed hosts)"},
				},
				Required: []string{"host"},
			},
		},
		{
			Name:        "ssh_session_exec",
			Description: "Execute a command in an existing session",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]property{
					"session_id": {Type: "string", Description: "Session ID from ssh_session_create"},
					"command":    {Type: "string", Description: "Command to execute"},
					"timeout":    {Type: "integer", Description: "Command timeout in seconds (default: 30, max: 300)"},
				},
				Required: []string{"session_id", "command"},
			},
		},
		{
			Name:        "ssh_session_close",
			Description: "Close an SSH session",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]property{
					"session_id": {Type: "string", Description: "Session ID to close"},
				},
				Required: []string{"session_id"},
			},
		},
	}
	sendResult(send, req.ID, toolsListResult{Tools: tools})
}

func (s *Server) handleToolsCall(req *jsonRPCRequest, client string, send sendFunc) {
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		sendError(send, req.ID, -32602, "Invalid params")
		return
	}

	// Enforce per-client rate limit on every tool call.
	if s.limiter != nil && !s.limiter.Allow(client) {
		sendError(send, req.ID, errCodeRateLimited,
			fmt.Sprintf("rate limit exceeded: max %d tool calls per %s",
				s.limiter.limit, s.limiter.window))
		return
	}

	switch params.Name {
	case "ssh_exec":
		s.toolSSHExec(req.ID, params.Arguments, client, send)
	case "ssh_session_create":
		s.toolSessionCreate(req.ID, params.Arguments, client, send)
	case "ssh_session_exec":
		s.toolSessionExec(req.ID, params.Arguments, client, send)
	case "ssh_session_close":
		s.toolSessionClose(req.ID, params.Arguments, client, send)
	default:
		sendError(send, req.ID, -32602, fmt.Sprintf("Unknown tool: %s", params.Name))
	}
}

// --- Tool implementations ---

// JSON-RPC error code returned when a request is rate limited.
const errCodeRateLimited = -32000

// checkSessionCap reports whether a new SSH session may be created. When the
// concurrent-session cap is reached it sends a tool error and returns false.
func (s *Server) checkSessionCap(id interface{}, send sendFunc) bool {
	if s.limiter == nil {
		return true
	}
	current := len(s.sessionMgr.ListSessions())
	if !s.limiter.AllowSession(current) {
		sendToolError(send, id,
			fmt.Sprintf("concurrent session limit exceeded: max %d sessions", s.limiter.MaxSessions()))
		return false
	}
	return true
}

func (s *Server) toolSSHExec(id interface{}, rawArgs json.RawMessage, client string, send sendFunc) {
	var input sshExecInput
	if err := json.Unmarshal(rawArgs, &input); err != nil {
		sendToolError(send, id, "invalid arguments: "+err.Error())
		return
	}

	if input.Host == "" || input.Command == "" {
		sendToolError(send, id, "host and command are required")
		return
	}

	// Validate host against whitelist
	if !s.isHostAllowed(input.Host) {
		log.Warnw("MCP ssh_exec rejected: host not in whitelist", "host", input.Host, "client", client)
		sendToolError(send, id, "host not in allowed hosts whitelist")
		return
	}

	// Enforce concurrent-session cap before opening a new connection.
	if !s.checkSessionCap(id, send) {
		return
	}

	// Resolve SSH config
	sshCfg, err := api.ResolveSSHConfig(input.Host)
	if err != nil {
		sendToolError(send, id, "failed to resolve SSH config: "+err.Error())
		return
	}

	// Create session owned by this client (other keys cannot drive it)
	sess, err := s.sessionMgr.CreateSession(input.Host, sshCfg, client)
	if err != nil {
		sendToolError(send, id, "SSH connection failed: "+err.Error())
		return
	}
	defer s.sessionMgr.RemoveSession(sess.ID)

	// Audit
	_ = s.auditLogger.LogAPIEvent(audit.EventAPISessionCreate, sess.ID, input.Host, client, "")

	// Execute
	timeout := s.resolveTimeout(input.Timeout)
	stdout, stderr, exitCode, err := sess.Exec(input.Command, timeout)
	if err != nil {
		sendToolError(send, id, "exec failed: "+err.Error())
		return
	}

	_ = s.auditLogger.LogAPIEvent(audit.EventAPIExec, sess.ID, input.Host, client, input.Command)

	result := map[string]interface{}{
		"exit_code": exitCode,
		"stdout":    stdout,
		"stderr":    stderr,
	}
	sendToolResult(send, id, result)
}

func (s *Server) toolSessionCreate(id interface{}, rawArgs json.RawMessage, client string, send sendFunc) {
	var input sshSessionCreateInput
	if err := json.Unmarshal(rawArgs, &input); err != nil {
		sendToolError(send, id, "invalid arguments: "+err.Error())
		return
	}

	if input.Host == "" {
		sendToolError(send, id, "host is required")
		return
	}

	// Validate host against whitelist
	if !s.isHostAllowed(input.Host) {
		log.Warnw("MCP ssh_session_create rejected: host not in whitelist", "host", input.Host, "client", client)
		sendToolError(send, id, "host not in allowed hosts whitelist")
		return
	}

	// Enforce concurrent-session cap before opening a new connection.
	if !s.checkSessionCap(id, send) {
		return
	}

	sshCfg, err := api.ResolveSSHConfig(input.Host)
	if err != nil {
		sendToolError(send, id, "failed to resolve SSH config: "+err.Error())
		return
	}

	sess, err := s.sessionMgr.CreateSession(input.Host, sshCfg, client)
	if err != nil {
		sendToolError(send, id, "SSH connection failed: "+err.Error())
		return
	}

	_ = s.auditLogger.LogAPIEvent(audit.EventAPISessionCreate, sess.ID, input.Host, client, "")

	result := map[string]interface{}{
		"session_id": sess.ID,
	}
	sendToolResult(send, id, result)
}

func (s *Server) toolSessionExec(id interface{}, rawArgs json.RawMessage, client string, send sendFunc) {
	var input sshSessionExecInput
	if err := json.Unmarshal(rawArgs, &input); err != nil {
		sendToolError(send, id, "invalid arguments: "+err.Error())
		return
	}

	if input.SessionID == "" || input.Command == "" {
		sendToolError(send, id, "session_id and command are required")
		return
	}

	// Ownership check: a session may only be driven by its creator.
	sess, ok := s.sessionMgr.GetSessionOwned(input.SessionID, client)
	if !ok {
		sendToolError(send, id, "session not found")
		return
	}

	if sess.State() != api.StateConnected {
		sendToolError(send, id, "session is not connected")
		return
	}

	timeout := s.resolveTimeout(input.Timeout)
	stdout, stderr, exitCode, err := sess.Exec(input.Command, timeout)
	if err != nil {
		sendToolError(send, id, "exec failed: "+err.Error())
		return
	}

	_ = s.auditLogger.LogAPIEvent(audit.EventAPIExec, sess.ID, sess.Host, client, input.Command)

	result := map[string]interface{}{
		"exit_code": exitCode,
		"stdout":    stdout,
		"stderr":    stderr,
	}
	sendToolResult(send, id, result)
}

func (s *Server) toolSessionClose(id interface{}, rawArgs json.RawMessage, client string, send sendFunc) {
	var input sshSessionCloseInput
	if err := json.Unmarshal(rawArgs, &input); err != nil {
		sendToolError(send, id, "invalid arguments: "+err.Error())
		return
	}

	if input.SessionID == "" {
		sendToolError(send, id, "session_id is required")
		return
	}

	// Ownership check: a session may only be closed by its creator.
	sess, ok := s.sessionMgr.GetSessionOwned(input.SessionID, client)
	if !ok {
		sendToolError(send, id, "session not found")
		return
	}

	host := sess.Host
	s.sessionMgr.RemoveSession(input.SessionID)

	_ = s.auditLogger.LogAPIEvent(audit.EventAPISessionClose, input.SessionID, host, client, "")

	result := map[string]interface{}{
		"success": true,
	}
	sendToolResult(send, id, result)
}

// --- Helpers ---

// resolveTimeout clamps a client-requested timeout (seconds) to sane bounds:
// default 30s, capped by the configured maximum exec timeout.
func (s *Server) resolveTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return 30 * time.Second
	}
	max := s.maxExecTimeout
	if max <= 0 {
		max = defaultMaxExecTimeout
	}
	if d := time.Duration(seconds) * time.Second; d < max {
		return d
	}
	return max
}

func sendResult(send sendFunc, id interface{}, result interface{}) {
	send(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func sendError(send sendFunc, id interface{}, code int, message string) {
	send(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	})
}

func sendToolResult(send sendFunc, id interface{}, result interface{}) {
	data, _ := json.Marshal(result)
	sendResult(send, id, toolCallResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func sendToolError(send sendFunc, id interface{}, message string) {
	sendResult(send, id, toolCallResult{
		Content: []contentBlock{{Type: "text", Text: message}},
		IsError: true,
	})
}

func (s *Server) writeResponse(resp jsonRPCResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(resp)
	if err != nil {
		log.Errorw("Failed to marshal MCP response", "error", err)
		return
	}

	_, _ = s.writer.Write(data)
	_ = s.writer.WriteByte('\n')
	_ = s.writer.Flush()
}

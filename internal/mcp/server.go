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
	sessionMgr   *api.SessionManager
	auditLogger  *audit.Logger
	apiKeyID     string
	allowedHosts map[string]bool
	limiter      *RateLimiter
	mu           sync.Mutex
	writer       *bufio.Writer
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
}

// Default rate limiting values.
const (
	DefaultRateLimit   = 10
	DefaultRateWindow  = time.Minute
	DefaultMaxSessions = 5
)

// NewServer creates a new MCP server.
func NewServer(cfg Config) (*Server, error) {
	auditLogger, err := audit.NewLogger(cfg.AuditLogPath, audit.Level(cfg.AuditLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
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

	return &Server{
		sessionMgr:   sessionMgr,
		auditLogger:  auditLogger,
		apiKeyID:     cfg.APIKeyID,
		allowedHosts: hostSet,
		limiter:      limiter,
		writer:       bufio.NewWriter(os.Stdout),
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
	Type       string                 `json:"type"`
	Properties map[string]property    `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
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
	Timeout   int     `json:"timeout,omitempty"`
}

type sshSessionCloseInput struct {
	SessionID string `json:"session_id"`
}

// Run starts the MCP server reading from stdin and writing to stdout.
func (s *Server) Run() error {
	scanner := bufio.NewScanner(os.Stdin)
	// Allow large messages
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, -32700, "Parse error")
			continue
		}

		s.handleRequest(&req)
	}

	return scanner.Err()
}

// Close cleans up server resources.
func (s *Server) Close() {
	s.sessionMgr.Close()
	s.auditLogger.Close()
	if s.limiter != nil {
		s.limiter.Close()
	}
}

func (s *Server) handleRequest(req *jsonRPCRequest) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "notifications/initialized":
		// No response needed for notifications
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(req)
	case "ping":
		s.sendResult(req.ID, map[string]interface{}{})
	default:
		s.sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func (s *Server) handleInitialize(req *jsonRPCRequest) {
	s.sendResult(req.ID, initializeResult{
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

func (s *Server) handleToolsList(req *jsonRPCRequest) {
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
	s.sendResult(req.ID, toolsListResult{Tools: tools})
}

// stdioClient is the rate-limit client identifier for the stdio transport.
// A stdio MCP server has a single connected client (the process on the other
// end of the pipe), so all tool calls share this identifier.
const stdioClient = "stdio"

func (s *Server) handleToolsCall(req *jsonRPCRequest) {
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, -32602, "Invalid params")
		return
	}

	// Enforce per-client rate limit on every tool call.
	if s.limiter != nil && !s.limiter.Allow(stdioClient) {
		s.sendError(req.ID, errCodeRateLimited,
			fmt.Sprintf("rate limit exceeded: max %d tool calls per %s",
				s.limiter.limit, s.limiter.window))
		return
	}

	switch params.Name {
	case "ssh_exec":
		s.toolSSHExec(req, params.Arguments)
	case "ssh_session_create":
		s.toolSessionCreate(req, params.Arguments)
	case "ssh_session_exec":
		s.toolSessionExec(req, params.Arguments)
	case "ssh_session_close":
		s.toolSessionClose(req, params.Arguments)
	default:
		s.sendError(req.ID, -32602, fmt.Sprintf("Unknown tool: %s", params.Name))
	}
}

// --- Tool implementations ---

// JSON-RPC error code returned when a request is rate limited.
const errCodeRateLimited = -32000

// checkSessionCap reports whether a new SSH session may be created. When the
// concurrent-session cap is reached it sends a tool error and returns false.
func (s *Server) checkSessionCap(req *jsonRPCRequest) bool {
	if s.limiter == nil {
		return true
	}
	current := len(s.sessionMgr.ListSessions())
	if !s.limiter.AllowSession(current) {
		s.sendToolError(req.ID,
			fmt.Sprintf("concurrent session limit exceeded: max %d sessions", s.limiter.MaxSessions()))
		return false
	}
	return true
}

func (s *Server) toolSSHExec(req *jsonRPCRequest, rawArgs json.RawMessage) {
	var input sshExecInput
	if err := json.Unmarshal(rawArgs, &input); err != nil {
		s.sendToolError(req.ID, "invalid arguments: "+err.Error())
		return
	}

	if input.Host == "" || input.Command == "" {
		s.sendToolError(req.ID, "host and command are required")
		return
	}

	// Validate host against whitelist
	if !s.isHostAllowed(input.Host) {
		s.sendToolError(req.ID, "host not in allowed hosts whitelist")
		return
	}

	// Enforce concurrent-session cap before opening a new connection.
	if !s.checkSessionCap(req) {
		return
	}

	// Resolve SSH config
	sshCfg, err := api.ResolveSSHConfig(input.Host)
	if err != nil {
		s.sendToolError(req.ID, "failed to resolve SSH config: "+err.Error())
		return
	}

	// Create session
	sess, err := s.sessionMgr.CreateSession(input.Host, sshCfg)
	if err != nil {
		s.sendToolError(req.ID, "SSH connection failed: "+err.Error())
		return
	}
	defer s.sessionMgr.RemoveSession(sess.ID)

	// Audit
	_ = s.auditLogger.LogAPIEvent(audit.EventAPISessionCreate, sess.ID, input.Host, s.apiKeyID, "")

	// Execute
	timeout := resolveTimeout(input.Timeout)
	stdout, stderr, exitCode, err := sess.Exec(input.Command, timeout)
	if err != nil {
		s.sendToolError(req.ID, "exec failed: "+err.Error())
		return
	}

	_ = s.auditLogger.LogAPIEvent(audit.EventAPIExec, sess.ID, input.Host, s.apiKeyID, input.Command)

	result := map[string]interface{}{
		"exit_code": exitCode,
		"stdout":    stdout,
		"stderr":    stderr,
	}
	s.sendToolResult(req.ID, result)
}

func (s *Server) toolSessionCreate(req *jsonRPCRequest, rawArgs json.RawMessage) {
	var input sshSessionCreateInput
	if err := json.Unmarshal(rawArgs, &input); err != nil {
		s.sendToolError(req.ID, "invalid arguments: "+err.Error())
		return
	}

	if input.Host == "" {
		s.sendToolError(req.ID, "host is required")
		return
	}

	// Validate host against whitelist
	if !s.isHostAllowed(input.Host) {
		s.sendToolError(req.ID, "host not in allowed hosts whitelist")
		return
	}

	// Enforce concurrent-session cap before opening a new connection.
	if !s.checkSessionCap(req) {
		return
	}

	sshCfg, err := api.ResolveSSHConfig(input.Host)
	if err != nil {
		s.sendToolError(req.ID, "failed to resolve SSH config: "+err.Error())
		return
	}

	sess, err := s.sessionMgr.CreateSession(input.Host, sshCfg)
	if err != nil {
		s.sendToolError(req.ID, "SSH connection failed: "+err.Error())
		return
	}

	_ = s.auditLogger.LogAPIEvent(audit.EventAPISessionCreate, sess.ID, input.Host, s.apiKeyID, "")

	result := map[string]interface{}{
		"session_id": sess.ID,
	}
	s.sendToolResult(req.ID, result)
}

func (s *Server) toolSessionExec(req *jsonRPCRequest, rawArgs json.RawMessage) {
	var input sshSessionExecInput
	if err := json.Unmarshal(rawArgs, &input); err != nil {
		s.sendToolError(req.ID, "invalid arguments: "+err.Error())
		return
	}

	if input.SessionID == "" || input.Command == "" {
		s.sendToolError(req.ID, "session_id and command are required")
		return
	}

	sess, ok := s.sessionMgr.GetSession(input.SessionID)
	if !ok {
		s.sendToolError(req.ID, "session not found")
		return
	}

	if sess.State != api.StateConnected {
		s.sendToolError(req.ID, "session is not connected")
		return
	}

	timeout := resolveTimeout(input.Timeout)
	stdout, stderr, exitCode, err := sess.Exec(input.Command, timeout)
	if err != nil {
		s.sendToolError(req.ID, "exec failed: "+err.Error())
		return
	}

	_ = s.auditLogger.LogAPIEvent(audit.EventAPIExec, sess.ID, sess.Host, s.apiKeyID, input.Command)

	result := map[string]interface{}{
		"exit_code": exitCode,
		"stdout":    stdout,
		"stderr":    stderr,
	}
	s.sendToolResult(req.ID, result)
}

func (s *Server) toolSessionClose(req *jsonRPCRequest, rawArgs json.RawMessage) {
	var input sshSessionCloseInput
	if err := json.Unmarshal(rawArgs, &input); err != nil {
		s.sendToolError(req.ID, "invalid arguments: "+err.Error())
		return
	}

	if input.SessionID == "" {
		s.sendToolError(req.ID, "session_id is required")
		return
	}

	sess, ok := s.sessionMgr.GetSession(input.SessionID)
	if !ok {
		s.sendToolError(req.ID, "session not found")
		return
	}

	host := sess.Host
	s.sessionMgr.RemoveSession(input.SessionID)

	_ = s.auditLogger.LogAPIEvent(audit.EventAPISessionClose, input.SessionID, host, s.apiKeyID, "")

	result := map[string]interface{}{
		"success": true,
	}
	s.sendToolResult(req.ID, result)
}

// --- Helpers ---

func resolveTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return 30 * time.Second
	}
	if seconds > 300 {
		return 300 * time.Second
	}
	return time.Duration(seconds) * time.Second
}

func (s *Server) sendResult(id interface{}, result interface{}) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	s.writeResponse(resp)
}

func (s *Server) sendError(id interface{}, code int, message string) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	}
	s.writeResponse(resp)
}

func (s *Server) sendToolResult(id interface{}, result interface{}) {
	data, _ := json.Marshal(result)
	s.sendResult(id, toolCallResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *Server) sendToolError(id interface{}, message string) {
	s.sendResult(id, toolCallResult{
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

// RunSSE starts the MCP server in SSE mode (HTTP-based).
// This is a placeholder for SSE transport support.
func (s *Server) RunSSE(addr string) error {
	// SSE transport would use net/http to serve Server-Sent Events
	// For now, only stdio is fully implemented
	return fmt.Errorf("SSE transport not yet implemented, use stdio mode")
}

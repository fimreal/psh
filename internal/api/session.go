package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/fimreal/goutils/ezap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/fimreal/psh/internal/netguard"
)

// SessionState represents the lifecycle state of an API session.
type SessionState string

const (
	StateConnecting SessionState = "connecting"
	StateConnected  SessionState = "connected"
	StateClosed     SessionState = "closed"
)

// APISession represents a single SSH session created via the API.
type APISession struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	CreatedAt time.Time `json:"created_at"`

	// stateMu guards state/lastActive: they are written by request
	// goroutines (Touch/connect/Close) and read by the manager's cleanup
	// goroutine, so unsynchronized access would be a data race.
	stateMu    sync.RWMutex
	state      SessionState
	lastActive time.Time

	// sessionKey is the per-session secret (not serialized).
	sessionKey string

	// ownerID identifies the API key / MCP client that created the session.
	// Sessions are only usable by their owner (not serialized).
	ownerID string

	// SSH connection
	sshClient *ssh.Client

	// Output broadcasting for attach observers
	outputBuf   *bytes.Buffer // ring buffer of recent output
	outputMu    sync.Mutex
	observers   map[chan []byte]struct{}
	observersMu sync.Mutex

	// Lifecycle
	closeOnce sync.Once
	closed    chan struct{}

	// Config reference for timeouts
	idleTimeout time.Duration
	maxLifetime time.Duration
}

// SessionManager manages in-memory API sessions with TTL.
type SessionManager struct {
	sessions    map[string]*APISession
	mu          sync.RWMutex
	idleTimeout time.Duration
	maxLifetime time.Duration
	stopCleanup chan struct{}
}

// NewSessionManager creates a new session manager and starts the cleanup goroutine.
func NewSessionManager(idleTimeout, maxLifetime time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions:    make(map[string]*APISession),
		idleTimeout: idleTimeout,
		maxLifetime: maxLifetime,
		stopCleanup: make(chan struct{}),
	}
	go sm.cleanupLoop()
	return sm
}

// Close stops the cleanup goroutine and closes all sessions.
func (sm *SessionManager) Close() {
	close(sm.stopCleanup)
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for id, sess := range sm.sessions {
		sess.Close()
		delete(sm.sessions, id)
	}
}

// CreateSession creates a new API session owned by ownerID (the API key or
// MCP client identifier) and connects to the given host.
func (sm *SessionManager) CreateSession(host string, sshConfig *SSHHostConfig, ownerID string) (*APISession, error) {
	sessionID, err := generateRandomHex(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	sessionKey, err := generateRandomHex(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session key: %w", err)
	}

	sess := &APISession{
		ID:          sessionID,
		Host:        host,
		CreatedAt:   time.Now(),
		sessionKey:  sessionKey,
		ownerID:     ownerID,
		outputBuf:   bytes.NewBuffer(nil),
		observers:   make(map[chan []byte]struct{}),
		closed:      make(chan struct{}),
		idleTimeout: sm.idleTimeout,
		maxLifetime: sm.maxLifetime,
	}
	sess.setState(StateConnecting)
	sess.Touch()

	// Connect to SSH host
	if err := sess.connect(sshConfig); err != nil {
		return nil, fmt.Errorf("SSH connection failed: %w", err)
	}

	sm.mu.Lock()
	sm.sessions[sessionID] = sess
	sm.mu.Unlock()

	return sess, nil
}

// GetSession returns a session by ID.
func (sm *SessionManager) GetSession(id string) (*APISession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessions[id]
	return sess, ok
}

// GetSessionOwned returns the session only if it was created by ownerID.
// Cross-tenant access must not reveal (or allow driving) other owners'
// sessions even when their IDs leak.
func (sm *SessionManager) GetSessionOwned(id, ownerID string) (*APISession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessions[id]
	if !ok || sess.ownerID != ownerID {
		return nil, false
	}
	return sess, true
}

// ListSessions returns all active sessions (global count, for caps/monitoring).
func (sm *SessionManager) ListSessions() []*APISession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]*APISession, 0, len(sm.sessions))
	for _, sess := range sm.sessions {
		result = append(result, sess)
	}
	return result
}

// ListSessionsByOwner returns all active sessions created by ownerID.
func (sm *SessionManager) ListSessionsByOwner(ownerID string) []*APISession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]*APISession, 0, len(sm.sessions))
	for _, sess := range sm.sessions {
		if sess.ownerID == ownerID {
			result = append(result, sess)
		}
	}
	return result
}

// RemoveSession closes and removes a session.
func (sm *SessionManager) RemoveSession(id string) {
	sm.mu.Lock()
	sess, ok := sm.sessions[id]
	if ok {
		delete(sm.sessions, id)
	}
	sm.mu.Unlock()
	if ok {
		sess.Close()
	}
}

// ValidateSessionKey checks the session key using constant-time comparison.
func (s *APISession) ValidateSessionKey(key string) bool {
	return subtle.ConstantTimeCompare([]byte(s.sessionKey), []byte(key)) == 1
}

// SessionKey returns the session key (only used at creation time).
func (s *APISession) SessionKey() string {
	return s.sessionKey
}

// Touch updates the last active timestamp.
func (s *APISession) Touch() {
	s.stateMu.Lock()
	s.lastActive = time.Now()
	s.stateMu.Unlock()
}

// State returns the current lifecycle state.
func (s *APISession) State() SessionState {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.state
}

// setState stores the lifecycle state.
func (s *APISession) setState(st SessionState) {
	s.stateMu.Lock()
	s.state = st
	s.stateMu.Unlock()
}

// LastActive returns the last activity timestamp.
func (s *APISession) LastActive() time.Time {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.lastActive
}

// Exec executes a command on the SSH session and returns stdout, stderr, exit code.
func (s *APISession) Exec(command string, timeout time.Duration) (stdout, stderr string, exitCode int, err error) {
	if s.State() != StateConnected {
		return "", "", -1, fmt.Errorf("session not connected")
	}
	if s.sshClient == nil {
		return "", "", -1, fmt.Errorf("SSH client not initialized")
	}

	s.Touch()

	sess, err := s.sshClient.NewSession()
	if err != nil {
		return "", "", -1, fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer sess.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	sess.Stdout = &stdoutBuf
	sess.Stderr = &stderrBuf

	// Use context for timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- sess.Run(command)
	}()

	select {
	case <-ctx.Done():
		// Timeout: signal the remote process
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return stdoutBuf.String(), stderrBuf.String(), -1, fmt.Errorf("command timed out after %v", timeout)
	case runErr := <-done:
		exitCode = 0
		if runErr != nil {
			if exitErr, ok := runErr.(*ssh.ExitError); ok {
				exitCode = exitErr.ExitStatus()
			} else {
				return stdoutBuf.String(), stderrBuf.String(), -1, runErr
			}
		}
		out := stdoutBuf.String()
		errOut := stderrBuf.String()
		// Broadcast output to observers
		s.broadcastOutput([]byte(out))
		if errOut != "" {
			s.broadcastOutput([]byte(errOut))
		}
		return out, errOut, exitCode, nil
	}
}

// Close closes the SSH connection and notifies observers.
func (s *APISession) Close() {
	s.closeOnce.Do(func() {
		s.setState(StateClosed)
		close(s.closed)

		// Notify observers
		s.observersMu.Lock()
		for ch := range s.observers {
			close(ch)
			delete(s.observers, ch)
		}
		s.observersMu.Unlock()

		// Close SSH client
		if s.sshClient != nil {
			_ = s.sshClient.Close()
		}
	})
}

// Attach adds a read-only observer channel.
func (s *APISession) Attach() (chan []byte, error) {
	select {
	case <-s.closed:
		return nil, fmt.Errorf("session already closed")
	default:
	}

	ch := make(chan []byte, 64)
	s.observersMu.Lock()
	s.observers[ch] = struct{}{}
	s.observersMu.Unlock()
	return ch, nil
}

// Detach removes an observer channel.
func (s *APISession) Detach(ch chan []byte) {
	s.observersMu.Lock()
	delete(s.observers, ch)
	s.observersMu.Unlock()
}

// broadcastOutput sends output to all attached observers.
func (s *APISession) broadcastOutput(data []byte) {
	if len(data) == 0 {
		return
	}
	// Store in buffer
	s.outputMu.Lock()
	s.outputBuf.Write(data)
	// Cap buffer at 1MB
	if s.outputBuf.Len() > 1024*1024 {
		excess := s.outputBuf.Len() - 1024*1024
		s.outputBuf.Next(excess)
	}
	s.outputMu.Unlock()

	// Send to observers (non-blocking)
	s.observersMu.Lock()
	for ch := range s.observers {
		select {
		case ch <- data:
		default:
			// Drop if observer is slow
		}
	}
	s.observersMu.Unlock()
}

// connect establishes the SSH connection.
func (s *APISession) connect(cfg *SSHHostConfig) error {
	var authMethods []ssh.AuthMethod

	// Try SSH key auth
	signers, err := loadSSHKeys(cfg.IdentityFile)
	if err == nil && len(signers) > 0 {
		for _, signer := range signers {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}

	// Try ssh-agent
	if agentSigners := loadSSHAgent(); len(agentSigners) > 0 {
		authMethods = append(authMethods, ssh.PublicKeys(agentSigners...))
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("no SSH authentication methods available for host %s", cfg.Hostname)
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()

	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(cfg.Hostname, fmt.Sprintf("%d", cfg.Port))

	// Pre-dial check for fast feedback (the dial-time netguard control below
	// is authoritative).
	if addrBlocked(addr) {
		return fmt.Errorf("host %s is blacklisted", cfg.Hostname)
	}

	// Dial manually so the Control hook can re-check the blacklist against
	// the RESOLVED address right before the TCP connect: a pre-dial hostname
	// check alone can be bypassed via DNS rebinding (public IP during
	// lookup, loopback during connect).
	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
		Control: netguard.ControlFunc(nil),
	}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("SSH dial to %s failed: %w", addr, err)
	}
	client, chans, reqs, err := ssh.NewClientConn(conn, addr, sshCfg)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SSH handshake to %s failed: %w", addr, err)
	}
	s.sshClient = ssh.NewClient(client, chans, reqs)
	s.setState(StateConnected)
	return nil
}

// cleanupLoop periodically removes expired sessions.
func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.stopCleanup:
			return
		case <-ticker.C:
			sm.cleanupExpired()
		}
	}
}

func (sm *SessionManager) cleanupExpired() {
	now := time.Now()
	var expired []string

	sm.mu.RLock()
	for id, sess := range sm.sessions {
		// Idle timeout
		if now.Sub(sess.LastActive()) > sm.idleTimeout {
			expired = append(expired, id)
			continue
		}
		// Max lifetime
		if now.Sub(sess.CreatedAt) > sm.maxLifetime {
			expired = append(expired, id)
		}
	}
	sm.mu.RUnlock()

	for _, id := range expired {
		log.Infow("API session expired", "session_id", id)
		sm.RemoveSession(id)
	}
}

// SSHHostConfig holds resolved SSH connection parameters.
type SSHHostConfig struct {
	Name         string
	Hostname     string
	User         string
	Port         int
	IdentityFile string
}

// ResolveSSHConfig resolves a host alias to SSH connection parameters
// using ~/.ssh/config.
func ResolveSSHConfig(host string) (*SSHHostConfig, error) {
	cfg := &SSHHostConfig{
		Name:     host,
		Hostname: host,
		User:     "root",
		Port:     22,
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return cfg, nil // Use defaults
	}

	configPath := filepath.Join(home, ".ssh", "config")
	file, err := os.Open(configPath)
	if err != nil {
		return cfg, nil // Use defaults
	}
	defer file.Close()

	var currentHost *SSHHostConfig
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		keyword := strings.ToLower(parts[0])
		value := parts[1]

		switch keyword {
		case "host":
			if currentHost != nil && currentHost.Name == host {
				applyConfig(cfg, currentHost)
				return cfg, nil
			}
			currentHost = &SSHHostConfig{Name: value, Hostname: value, Port: 22}
		case "hostname":
			if currentHost != nil {
				currentHost.Hostname = value
			}
		case "user":
			if currentHost != nil {
				currentHost.User = value
			}
		case "port":
			if currentHost != nil {
				fmt.Sscanf(value, "%d", &currentHost.Port)
			}
		case "identityfile":
			if currentHost != nil && len(parts) > 1 {
				path := parts[1]
				if strings.HasPrefix(path, "~") {
					path = filepath.Join(home, path[1:])
				}
				currentHost.IdentityFile = path
			}
		}
	}

	if currentHost != nil && currentHost.Name == host {
		applyConfig(cfg, currentHost)
	}
	return cfg, nil
}

func applyConfig(target, source *SSHHostConfig) {
	if source.Hostname != source.Name {
		target.Hostname = source.Hostname
	}
	if source.User != "" {
		target.User = source.User
	}
	if source.Port != 0 {
		target.Port = source.Port
	}
	if source.IdentityFile != "" {
		target.IdentityFile = source.IdentityFile
	}
}

// loadSSHKeys loads SSH private keys from the given path or default locations.
func loadSSHKeys(identityFile string) ([]ssh.Signer, error) {
	var paths []string
	if identityFile != "" {
		paths = append(paths, identityFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		paths = append(paths,
			// Dedicated psh key first: when present it is the preferred
			// identity for API/MCP-initiated connections.
			filepath.Join(home, ".ssh", "id_ed25519_psh"),
			filepath.Join(home, ".ssh", "id_rsa"),
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_ecdsa"),
		)
	}

	var signers []ssh.Signer
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			continue
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

// loadSSHAgent tries to connect to ssh-agent and get signers.
func loadSSHAgent() []ssh.Signer {
	// ssh-agent support via SSH_AUTH_SOCK
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil
	}
	// Use golang.org/x/crypto/ssh/agent
	agentClient := agent.NewClient(conn)
	signers, err := agentClient.Signers()
	if err != nil {
		conn.Close()
		return nil
	}
	return signers
}

// addrBlocked checks whether the address resolves to (or is literally) an
// always-blocked destination. The dial-time netguard control is the real
// enforcement; this only gives faster, clearer errors.
func addrBlocked(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return netguard.IsBlockedIP(ip)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if netguard.IsBlockedIP(ip) {
			return true
		}
	}
	return false
}

// generateRandomHex generates a random hex string of the given byte length.
func generateRandomHex(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

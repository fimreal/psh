package shell

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/fimreal/goutils/ezap"
	"golang.org/x/crypto/ssh"
)

// HostConfig represents an SSH host configuration
type HostConfig struct {
	Name         string
	Hostname     string
	User         string
	Port         int
	IdentityFile string
}

type Session struct {
	sshClient *ssh.Client
	sshSess   *ssh.Session
	sshStdin  io.WriteCloser
	sshStdout io.Reader

	outputChan chan []byte
	done       chan struct{}
	mu         sync.Mutex
	lineBuf    *bytes.Buffer
	cols       int
	rows       int
	hosts      map[string]HostConfig

	// Password prompt state
	awaitingPassword bool
	pendingSSHUser   string
	pendingSSHHost   string
	pendingSSHPort   int
	pendingSigners   []ssh.Signer

	// SSH connection cancellation
	connecting      bool
	cancelConnect   context.CancelFunc
	connectCancelMu sync.Mutex

	// SSH security
	sshBlacklist      []*net.IPNet
	strictHostKey     bool // Reject unknown hosts instead of auto-accepting
	showHostKeyDigest bool // Show fingerprint when connecting

	// Command history
	cmdHistory []string
	historyIdx int
	savedLine  string // line saved before browsing history

	// Callback for SSH connection
	OnSSHConnect func(host string)
}

// NewSession creates a restricted shell session
func NewSession(blacklist []string, strictHostKey, showHostKeyDigest bool) *Session {
	s := &Session{
		outputChan:        make(chan []byte, 256),
		done:              make(chan struct{}),
		lineBuf:           &bytes.Buffer{},
		cols:              80,
		rows:              24,
		hosts:             make(map[string]HostConfig),
		sshBlacklist:      parseBlacklist(blacklist),
		strictHostKey:     strictHostKey,
		showHostKeyDigest: showHostKeyDigest,
	}
	s.loadSSHConfig()
	return s
}

// parseBlacklist converts CIDR strings to IPNet slices
func parseBlacklist(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warnw("Invalid CIDR in SSH blacklist", "cidr", cidr, "error", err)
			continue
		}
		nets = append(nets, ipNet)
	}
	return nets
}

// isBlacklisted checks if an IP address is in the blacklist
func (s *Session) isBlacklisted(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		// Try to resolve hostname
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return false
		}
		ip = ips[0]
	}

	for _, ipNet := range s.sshBlacklist {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// Start begins the shell interaction
func (s *Session) Start() {
	s.printWelcome()
}

var helpText = "\r\nAvailable Commands:\r\n\r\n" +
	"  ssh user@host[:port]       Connect with SSH key\r\n" +
	"  ssh hostname               Connect using ~/.ssh/config\r\n" +
	"  help                       Show this help\r\n" +
	"  clear                      Clear screen\r\n" +
	"  exit                       Close session\r\n\r\n"

func (s *Session) printWelcome() {
	s.outputChan <- []byte("psh - WebSSH Shell\r\n")
	s.outputChan <- []byte(helpText)
	s.outputChan <- []byte("$ ")
}

func (s *Session) loadSSHConfig() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	configPath := filepath.Join(home, ".ssh", "config")
	file, err := os.Open(configPath)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	var currentHost *HostConfig

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
			if currentHost != nil {
				s.hosts[currentHost.Name] = *currentHost
			}
			currentHost = &HostConfig{
				Name:     value,
				Hostname: value,
				Port:     22,
			}
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
				if _, err := fmt.Sscanf(value, "%d", &currentHost.Port); err != nil {
					currentHost.Port = 22
				}
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

	if currentHost != nil {
		s.hosts[currentHost.Name] = *currentHost
	}
}

// Write handles user input
func (s *Session) Write(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ctrl+C during connection attempt - cancel the connection
	if len(data) == 1 && data[0] == 0x03 && s.connecting {
		s.connectCancelMu.Lock()
		if s.cancelConnect != nil {
			s.cancelConnect()
			s.cancelConnect = nil
		}
		s.connectCancelMu.Unlock()
		return nil
	}

	if s.sshClient != nil {
		if s.sshStdin != nil {
			if _, err := s.sshStdin.Write(data); err != nil {
				return err
			}
		}
		return nil
	}

	// Handle password input
	if s.awaitingPassword {
		for _, b := range data {
			if b == '\n' || b == '\r' {
				password := s.lineBuf.String()
				s.lineBuf.Reset()
				s.savedLine = "" // Clear saved line to prevent password leakage
				s.awaitingPassword = false
				s.outputChan <- []byte("\r\n")
				go s.connectWithPassword(password)
			} else if b == 127 || b == 8 {
				if s.lineBuf.Len() > 0 {
					s.lineBuf.Truncate(s.lineBuf.Len() - 1)
					// Don't echo anything for password
				}
			} else if b >= 32 {
				s.lineBuf.WriteByte(b)
				// Don't echo password characters
			}
		}
		return nil
	}

	// Handle arrow keys for command history (up/down only)
	if len(data) == 3 && data[0] == 0x1b && data[1] == '[' {
		switch data[2] {
		case 'A': // Up arrow
			s.navigateHistory(-1)
			return nil
		case 'B': // Down arrow
			s.navigateHistory(1)
			return nil
		}
	}
	// Other escape sequences (ESC key, left/right arrows, etc.)
	if len(data) >= 1 && data[0] == 0x1b {
		return nil
	}

	// Process input data, handling control characters and UTF-8
	for i := 0; i < len(data); {
		b := data[i]
		if b == '\n' || b == '\r' {
			cmd := strings.TrimSpace(s.lineBuf.String())
			s.lineBuf.Reset()
			// Reset history index and save command
			s.historyIdx = len(s.cmdHistory)
			s.savedLine = ""
			if cmd != "" {
				// Add to history if different from last command
				if len(s.cmdHistory) == 0 || s.cmdHistory[len(s.cmdHistory)-1] != cmd {
					s.cmdHistory = append(s.cmdHistory, cmd)
				}
				go s.executeCommand(cmd)
			} else {
				s.printPrompt()
			}
			i++
		} else if b == 127 || b == 8 {
			// Backspace - delete last character
			if s.lineBuf.Len() > 0 {
				lastBytes := s.lineBuf.Bytes()
				// Find start of last UTF-8 character
				j := len(lastBytes) - 1
				for j > 0 && (lastBytes[j]&0xC0) == 0x80 {
					j--
				}
				s.lineBuf.Truncate(j)
				s.outputChan <- []byte("\b \b")
			}
			i++
		} else if b >= 32 && b < 127 {
			// ASCII printable characters
			s.lineBuf.WriteByte(b)
			s.outputChan <- []byte{b}
			i++
		} else if b >= 0x80 {
			// UTF-8 multi-byte character: collect all bytes
			charLen := 1
			if b >= 0xC0 && b < 0xE0 {
				charLen = 2
			} else if b >= 0xE0 && b < 0xF0 {
				charLen = 3
			} else if b >= 0xF0 && b < 0xF8 {
				charLen = 4
			}
			if i+charLen <= len(data) {
				charBytes := data[i : i+charLen]
				s.lineBuf.Write(charBytes)
				s.outputChan <- charBytes
				i += charLen
			} else {
				i++
			}
		} else {
			i++
		}
	}

	return nil
}

// navigateHistory handles up/down arrow key navigation through command history
func (s *Session) navigateHistory(direction int) {
	if len(s.cmdHistory) == 0 {
		return
	}

	// Save current line when first navigating
	if s.historyIdx == len(s.cmdHistory) {
		s.savedLine = s.lineBuf.String()
	}

	// Calculate new index
	newIdx := s.historyIdx + direction
	if newIdx < 0 {
		newIdx = 0
	} else if newIdx > len(s.cmdHistory) {
		newIdx = len(s.cmdHistory)
	}

	// If no change, return
	if newIdx == s.historyIdx {
		return
	}

	s.historyIdx = newIdx

	// Clear current line by sending backspaces
	lineLen := s.lineBuf.Len()
	for i := 0; i < lineLen; i++ {
		s.outputChan <- []byte("\b \b")
	}

	// Set new content
	var newContent string
	if newIdx == len(s.cmdHistory) {
		newContent = s.savedLine
	} else {
		newContent = s.cmdHistory[newIdx]
	}

	s.lineBuf.Reset()
	s.lineBuf.WriteString(newContent)
	s.outputChan <- []byte(newContent)
}

func (s *Session) executeCommand(cmd string) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		s.printPrompt()
		return
	}

	switch parts[0] {
	case "help", "?":
		s.showHelp()
	case "exit", "quit", "logout":
		s.outputChan <- []byte("\r\nGoodbye!\r\n")
		close(s.done)
	case "ssh":
		if len(parts) < 2 {
			s.outputChan <- []byte("\r\nUsage: ssh [user@]hostname[:port] or ssh -p port [user@]hostname\r\n")
			s.printPrompt()
			return
		}
		target, port := parseSSHArgs(parts[1:])
		s.connectSSH(target, port)
	case "clear":
		s.outputChan <- []byte("\x1b[2J\x1b[H")
		s.printPrompt()
	default:
		s.outputChan <- fmt.Appendf(nil, "\r\nUnknown command: %s\r\n", parts[0])
		s.outputChan <- []byte("Type 'help' for available commands\r\n")
		s.printPrompt()
	}
}

func (s *Session) showHelp() {
	s.outputChan <- []byte(helpText)

	if len(s.hosts) > 0 {
		s.outputChan <- []byte("Configured hosts from ~/.ssh/config:\r\n")
		for name, h := range s.hosts {
			s.outputChan <- fmt.Appendf(nil, "  %-15s %s@%s:%d\r\n", name, h.User, h.Hostname, h.Port)
		}
		s.outputChan <- []byte("\r\n")
	}

	s.outputChan <- []byte("Examples:\r\n")
	s.outputChan <- []byte("  ssh root@192.168.1.1\r\n")
	s.outputChan <- []byte("  ssh -p 2222 admin@server.com\r\n")
	s.outputChan <- []byte("  ssh admin@server.com:2222\r\n")
	s.outputChan <- []byte("  ssh myserver\r\n\r\n")
	s.printPrompt()
}

// parseSSHArgs parses SSH arguments and returns target and port
// Supports: ssh user@host, ssh -p port user@host, ssh -pport user@host, ssh host, ssh -p port host
func parseSSHArgs(args []string) (target string, port int) {
	port = 0 // 0 means no port specified, will use default or from target
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-p" && i+1 < len(args) {
			// -p with space: ssh -p 2222 host
			if p, err := fmt.Sscanf(args[i+1], "%d", &port); p != 1 || err != nil {
				port = 0
			}
			i++ // skip port value
		} else if strings.HasPrefix(arg, "-p") && len(arg) > 2 {
			// -p without space: ssh -p2222 host
			if p, err := fmt.Sscanf(arg[2:], "%d", &port); p != 1 || err != nil {
				port = 0
			}
		} else if !strings.HasPrefix(arg, "-") {
			target = arg
		}
	}
	return target, port
}

func (s *Session) connectSSH(target string, explicitPort int) {
	var sshUser, host string
	port := 22
	var identityFile string

	if hc, ok := s.hosts[target]; ok {
		sshUser = hc.User
		host = hc.Hostname
		port = hc.Port
		identityFile = hc.IdentityFile
		// -p parameter overrides config port
		if explicitPort > 0 {
			port = explicitPort
		}
		s.outputChan <- fmt.Appendf(nil, "\r\nConnecting to %s (%s@%s:%d)...\r\n", target, sshUser, host, port)
	} else {
		if idx := strings.Index(target, "@"); idx > 0 {
			sshUser = target[:idx]
			host = target[idx+1:]
		} else {
			sshUser = "root"
			host = target
		}

		// Parse port from host:port format
		if idx := strings.Index(host, ":"); idx > 0 {
			if _, err := fmt.Sscanf(host[idx+1:], "%d", &port); err != nil {
				port = 22
			}
			host = host[:idx]
		}

		// -p parameter overrides host:port
		if explicitPort > 0 {
			port = explicitPort
		}

		s.outputChan <- fmt.Appendf(nil, "\r\nConnecting to %s@%s:%d...\r\n", sshUser, host, port)
	}

	// Check if host is blacklisted
	if s.isBlacklisted(host) {
		s.outputChan <- []byte("Error: SSH to this address is not allowed (blacklisted)\r\n")
		s.printPrompt()
		return
	}

	home, _ := os.UserHomeDir()
	keyFiles := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
	}
	if identityFile != "" {
		keyFiles = append([]string{identityFile}, keyFiles...)
	}

	var signers []ssh.Signer
	for _, keyFile := range keyFiles {
		if data, err := os.ReadFile(keyFile); err == nil {
			if signer, err := ssh.ParsePrivateKey(data); err == nil {
				signers = append(signers, signer)
			}
		}
	}

	s.mu.Lock()
	s.pendingSSHUser = sshUser
	s.pendingSSHHost = host
	s.pendingSSHPort = port
	s.pendingSigners = signers
	s.mu.Unlock()

	if len(signers) > 0 {
		s.outputChan <- []byte("Trying SSH key authentication...\r\n")
		s.tryConnect(host, port, []ssh.AuthMethod{ssh.PublicKeys(signers...)})
		return
	}

	s.promptPassword()
}

func (s *Session) promptPassword() {
	s.mu.Lock()
	s.awaitingPassword = true
	s.mu.Unlock()
	s.outputChan <- []byte("Password: ")
}

func (s *Session) connectWithPassword(password string) {
	config := &ssh.ClientConfig{
		User: s.pendingSSHUser,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return s.verifyHostKey(hostname, key)
		},
		Timeout: 10 * time.Second,
	}

	s.tryConnectWithFallback(s.pendingSSHHost, s.pendingSSHPort, config.Auth, false)
}

func (s *Session) tryConnect(host string, port int, authMethods []ssh.AuthMethod) {
	s.tryConnectWithFallback(host, port, authMethods, true)
}

func (s *Session) tryConnectWithFallback(host string, port int, authMethods []ssh.AuthMethod, allowPasswordFallback bool) {
	// Create context for cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Store cancel function for Ctrl+C
	s.connectCancelMu.Lock()
	s.connecting = true
	s.cancelConnect = cancel
	s.connectCancelMu.Unlock()

	// Cleanup on exit
	defer func() {
		s.connectCancelMu.Lock()
		s.connecting = false
		s.cancelConnect = nil
		s.connectCancelMu.Unlock()
	}()

	config := &ssh.ClientConfig{
		User: s.pendingSSHUser,
		Auth: authMethods,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return s.verifyHostKey(hostname, key)
		},
		Timeout: 0, // We use context for timeout
	}

	// Connect with context support
	addr := fmt.Sprintf("%s:%d", host, port)

	// Use net.DialContext for cancellable connection
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() == context.Canceled {
			s.outputChan <- []byte("\r\nConnection cancelled.\r\n")
			s.printPrompt()
			return
		}
		// Check if this was a key auth failure and we should prompt for password
		if allowPasswordFallback && strings.Contains(err.Error(), "unable to authenticate") {
			s.outputChan <- []byte("SSH key authentication failed.\r\n")
			s.promptPassword()
			return
		}
		s.outputChan <- fmt.Appendf(nil, "\r\nConnection failed: %s\r\n", err)
		s.printPrompt()
		return
	}

	// Establish SSH connection
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		if ctx.Err() == context.Canceled {
			s.outputChan <- []byte("\r\nConnection cancelled.\r\n")
			s.printPrompt()
			return
		}
		if allowPasswordFallback && strings.Contains(err.Error(), "unable to authenticate") {
			s.outputChan <- []byte("SSH key authentication failed.\r\n")
			s.promptPassword()
			return
		}
		s.outputChan <- fmt.Appendf(nil, "\r\nSSH handshake failed: %s\r\n", err)
		s.printPrompt()
		return
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	// Create session
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		s.outputChan <- fmt.Appendf(nil, "\r\nSession error: %s\r\n", err)
		s.printPrompt()
		return
	}

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()

	// Request PTY with current terminal size (h, w order!)
	s.mu.Lock()
	cols, rows := s.cols, s.rows
	s.mu.Unlock()

	log.Debugw("SSH PTY request", "cols", cols, "rows", rows)

	if err := session.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{}); err != nil {
		_ = client.Close()
		s.outputChan <- fmt.Appendf(nil, "\r\nPTY request failed: %s\r\n", err)
		s.printPrompt()
		return
	}

	// Start shell
	if err := session.Shell(); err != nil {
		_ = client.Close()
		s.outputChan <- fmt.Appendf(nil, "\r\nShell start failed: %s\r\n", err)
		s.printPrompt()
		return
	}

	s.mu.Lock()
	s.sshClient = client
	s.sshSess = session
	s.sshStdin = stdin
	s.sshStdout = stdout
	s.mu.Unlock()

	s.outputChan <- []byte("\r\nConnected!\r\n")

	// Notify SSH connection
	if s.OnSSHConnect != nil {
		s.OnSSHConnect(host)
	}

	go s.sshOutputReader()
}

func (s *Session) sshOutputReader() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-s.done:
			return
		default:
			if s.sshStdout == nil {
				return
			}
			n, err := s.sshStdout.Read(buf)
			if n > 0 {
				s.outputChan <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				s.disconnectSSH()
				s.outputChan <- []byte("\r\nSSH session closed.\r\n")
				s.printPrompt()
				return
			}
		}
	}
}

func (s *Session) disconnectSSH() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sshSess != nil {
		_ = s.sshSess.Close()
		s.sshSess = nil
	}
	if s.sshClient != nil {
		_ = s.sshClient.Close()
		s.sshClient = nil
	}
	s.sshStdin = nil
	s.sshStdout = nil
}

func (s *Session) verifyHostKey(hostname string, key ssh.PublicKey) error {
	home, _ := os.UserHomeDir()
	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")

	fingerprint := ssh.FingerprintSHA256(key)

	// Show fingerprint for transparency (helps detect MITM)
	if s.showHostKeyDigest {
		s.outputChan <- fmt.Appendf(nil, "\r\nHost key: %s %s\r\n", key.Type(), fingerprint)
	}

	// Check if known_hosts exists
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		if s.strictHostKey {
			s.outputChan <- []byte("Error: Unknown host key and strict mode enabled.\r\n")
			s.outputChan <- []byte("Add the host to ~/.ssh/known_hosts manually or disable strict mode.\r\n")
			s.printPrompt()
			return fmt.Errorf("unknown host key (strict mode)")
		}
		s.outputChan <- fmt.Appendf(nil, "New host for %s - auto-accepting\r\n", hostname)
		return s.addHostKey(hostname, key, knownHostsPath)
	}

	// Read and check known_hosts
	data, err := os.ReadFile(knownHostsPath)
	if err != nil {
		if s.strictHostKey {
			s.outputChan <- []byte("Error: Cannot read known_hosts and strict mode enabled.\r\n")
			s.printPrompt()
			return fmt.Errorf("cannot read known_hosts (strict mode)")
		}
		return s.addHostKey(hostname, key, knownHostsPath)
	}

	keyBytes := key.Marshal()
	keyStr := base64.StdEncoding.EncodeToString(keyBytes)

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 3 {
			hosts := strings.Split(parts[0], ",")
			for _, h := range hosts {
				if h == hostname {
					if parts[2] == keyStr {
						return nil // Key matches
					}
					// Key mismatch - potential MITM attack
					s.outputChan <- []byte("\r\n\x1b[31mWARNING: HOST KEY MISMATCH!\x1b[0m\r\n")
					s.outputChan <- []byte("This could indicate a man-in-the-middle attack.\r\n")
					s.outputChan <- []byte("Remove the old key from ~/.ssh/known_hosts if this is expected.\r\n")
					s.printPrompt()
					return fmt.Errorf("host key mismatch for %s", hostname)
				}
			}
		}
	}

	// Key not found
	if s.strictHostKey {
		s.outputChan <- fmt.Appendf(nil, "Error: Unknown host key for %s (strict mode)\r\n", hostname)
		s.outputChan <- []byte("Add to known_hosts manually or connect without strict mode.\r\n")
		s.printPrompt()
		return fmt.Errorf("unknown host key (strict mode)")
	}

	// Auto-accept new key (default behavior for compatibility)
	s.outputChan <- fmt.Appendf(nil, "New host key for %s\r\n", hostname)
	s.outputChan <- []byte("Accepting and adding to known_hosts...\r\n")
	return s.addHostKey(hostname, key, knownHostsPath)
}

func (s *Session) addHostKey(hostname string, key ssh.PublicKey, knownHostsPath string) error {
	sshDir := filepath.Dir(knownHostsPath)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}

	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	keyType := key.Type()
	keyBytes := key.Marshal()
	line := fmt.Sprintf("%s %s %s", hostname, keyType, base64.StdEncoding.EncodeToString(keyBytes))
	_, err = fmt.Fprintln(f, line)
	return err
}

func (s *Session) printPrompt() {
	s.outputChan <- []byte("\r\n$ ")
}

func (s *Session) Read(buf []byte) (int, error) {
	select {
	case data := <-s.outputChan:
		n := copy(buf, data)
		return n, nil
	case <-s.done:
		return 0, io.EOF
	}
}

func (s *Session) Resize(cols, rows int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cols = cols
	s.rows = rows

	if s.sshSess != nil {
		// WindowChange takes (h, w) = (rows, cols)
		return s.sshSess.WindowChange(rows, cols)
	}
	return nil
}

func (s *Session) Close() error {
	select {
	case <-s.done:
		return nil
	default:
		close(s.done)
	}

	s.disconnectSSH()
	return nil
}

func (s *Session) Done() <-chan struct{} {
	return s.done
}

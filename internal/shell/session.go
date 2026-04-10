package shell

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
}

// NewSession creates a restricted shell session
func NewSession() *Session {
	s := &Session{
		outputChan: make(chan []byte, 256),
		done:       make(chan struct{}),
		lineBuf:    &bytes.Buffer{},
		cols:       80,
		rows:       24,
		hosts:      make(map[string]HostConfig),
	}
	s.loadSSHConfig()
	return s
}

// Start begins the shell interaction
func (s *Session) Start() {
	s.printWelcome()
}

func (s *Session) printWelcome() {
	s.outputChan <- []byte("psh - WebSSH Shell\r\n\r\n")
	s.outputChan <- []byte("Commands:\r\n")
	s.outputChan <- []byte("  ssh user@host[:port]       Connect with SSH key\r\n")
	s.outputChan <- []byte("  ssh hostname               Connect using ~/.ssh/config\r\n")
	s.outputChan <- []byte("  help                       Show this help\r\n")
	s.outputChan <- []byte("  clear                      Clear screen\r\n")
	s.outputChan <- []byte("  exit                       Close session\r\n\r\n")
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

	for _, b := range data {
		if b == '\n' || b == '\r' {
			cmd := strings.TrimSpace(s.lineBuf.String())
			s.lineBuf.Reset()
			if cmd != "" {
				go s.executeCommand(cmd)
			} else {
				s.printPrompt()
			}
		} else if b == 127 || b == 8 {
			if s.lineBuf.Len() > 0 {
				s.lineBuf.Truncate(s.lineBuf.Len() - 1)
				s.outputChan <- []byte("\b \b")
			}
		} else if b >= 32 {
			s.lineBuf.WriteByte(b)
			s.outputChan <- []byte{b}
		}
	}

	return nil
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
			s.outputChan <- []byte("\r\nUsage: ssh user@host[:port] or ssh hostname\r\n")
			s.printPrompt()
			return
		}
		s.connectSSH(parts[1])
	case "clear":
		s.outputChan <- []byte("\x1b[2J\x1b[H")
		s.printPrompt()
	default:
		s.outputChan <- []byte(fmt.Sprintf("\r\nUnknown command: %s\r\n", parts[0]))
		s.outputChan <- []byte("Type 'help' for available commands\r\n")
		s.printPrompt()
	}
}

func (s *Session) showHelp() {
	s.outputChan <- []byte("\r\nAvailable Commands:\r\n\r\n")
	s.outputChan <- []byte("  ssh user@host[:port]       Connect with SSH key\r\n")
	s.outputChan <- []byte("  ssh hostname               Connect using ~/.ssh/config\r\n")
	s.outputChan <- []byte("  help                       Show this help\r\n")
	s.outputChan <- []byte("  clear                      Clear screen\r\n")
	s.outputChan <- []byte("  exit                       Close session\r\n\r\n")

	if len(s.hosts) > 0 {
		s.outputChan <- []byte("Configured hosts from ~/.ssh/config:\r\n")
		for name, h := range s.hosts {
			s.outputChan <- []byte(fmt.Sprintf("  %-15s %s@%s:%d\r\n", name, h.User, h.Hostname, h.Port))
		}
		s.outputChan <- []byte("\r\n")
	}

	s.outputChan <- []byte("Examples:\r\n")
	s.outputChan <- []byte("  ssh root@192.168.1.1\r\n")
	s.outputChan <- []byte("  ssh admin@server.com:2222\r\n")
	s.outputChan <- []byte("  ssh myserver\r\n\r\n")
	s.printPrompt()
}

func (s *Session) connectSSH(target string) {
	var sshUser, host string
	var port = 22
	var identityFile string

	// Check if target is a host alias from config
	if hc, ok := s.hosts[target]; ok {
		sshUser = hc.User
		host = hc.Hostname
		port = hc.Port
		identityFile = hc.IdentityFile
		s.outputChan <- []byte(fmt.Sprintf("\r\nConnecting to %s (%s@%s:%d)...\r\n", target, sshUser, host, port))
	} else {
		// Parse [user@]host[:port]
		if idx := strings.Index(target, "@"); idx > 0 {
			sshUser = target[:idx]
			host = target[idx+1:]
		} else {
			sshUser = "root"
			host = target
		}

		if idx := strings.Index(host, ":"); idx > 0 {
			if _, err := fmt.Sscanf(host[idx+1:], "%d", &port); err != nil {
				port = 22
			}
			host = host[:idx]
		}

		s.outputChan <- []byte(fmt.Sprintf("\r\nConnecting to %s@%s:%d...\r\n", sshUser, host, port))
	}

	// Load SSH keys
	home, _ := os.UserHomeDir()
	var keyFiles []string

	if identityFile != "" {
		keyFiles = append(keyFiles, identityFile)
	}
	keyFiles = append(keyFiles,
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
	)

	var signers []ssh.Signer
	for _, keyFile := range keyFiles {
		if data, err := os.ReadFile(keyFile); err == nil {
			if signer, err := ssh.ParsePrivateKey(data); err == nil {
				signers = append(signers, signer)
			}
		}
	}

	// Save connection info for password fallback
	s.mu.Lock()
	s.pendingSSHUser = sshUser
	s.pendingSSHHost = host
	s.pendingSSHPort = port
	s.pendingSigners = signers
	s.mu.Unlock()

	// Try connecting with keys first
	if len(signers) > 0 {
		s.outputChan <- []byte("Trying SSH key authentication...\r\n")
		s.tryConnect(sshUser, host, port, []ssh.AuthMethod{ssh.PublicKeys(signers...)})
		return
	}

	// No keys found, prompt for password
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

	s.tryConnectWithFallback(s.pendingSSHUser, s.pendingSSHHost, s.pendingSSHPort, config.Auth, false)
}

func (s *Session) tryConnect(sshUser, host string, port int, authMethods []ssh.AuthMethod) {
	s.tryConnectWithFallback(sshUser, host, port, authMethods, true)
}

func (s *Session) tryConnectWithFallback(sshUser, host string, port int, authMethods []ssh.AuthMethod, allowPasswordFallback bool) {
	// SSH config
	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: authMethods,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return s.verifyHostKey(hostname, key)
		},
		Timeout: 10 * time.Second,
	}

	// Connect
	addr := fmt.Sprintf("%s:%d", host, port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		// Check if this was a key auth failure and we should prompt for password
		if allowPasswordFallback && strings.Contains(err.Error(), "unable to authenticate") {
			s.outputChan <- []byte("SSH key authentication failed.\r\n")
			s.promptPassword()
			return
		}
		s.outputChan <- []byte(fmt.Sprintf("\r\nConnection failed: %s\r\n", err))
		s.printPrompt()
		return
	}

	// Create session
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		s.outputChan <- []byte(fmt.Sprintf("\r\nSession error: %s\r\n", err))
		s.printPrompt()
		return
	}

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()

	// Request PTY
	if err := session.RequestPty("xterm-256color", s.cols, s.rows, ssh.TerminalModes{}); err != nil {
		_ = client.Close()
		s.outputChan <- []byte(fmt.Sprintf("\r\nPTY request failed: %s\r\n", err))
		s.printPrompt()
		return
	}

	// Start shell
	if err := session.Shell(); err != nil {
		_ = client.Close()
		s.outputChan <- []byte(fmt.Sprintf("\r\nShell start failed: %s\r\n", err))
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

	// Check if known_hosts exists
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		s.outputChan <- []byte(fmt.Sprintf("\r\nNew host key for %s - auto-accepting\r\n", hostname))
		return s.addHostKey(hostname, key, knownHostsPath)
	}

	// Read and check known_hosts
	data, err := os.ReadFile(knownHostsPath)
	if err != nil {
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
						return nil
					}
				}
			}
		}
	}

	// Key not found - auto-accept
	s.outputChan <- []byte(fmt.Sprintf("\r\nNew host key for %s\r\n", hostname))
	s.outputChan <- []byte(fmt.Sprintf("Fingerprint: %s\r\n", ssh.FingerprintSHA256(key)))
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
		return s.sshSess.WindowChange(cols, rows)
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

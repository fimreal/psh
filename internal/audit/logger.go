package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/fimreal/goutils/ezap"
)

type EventType string

const (
	EventConnection    EventType = "connection"
	EventDisconnection EventType = "disconnection"
	EventError         EventType = "error"
	EventCommand       EventType = "command"
)

// Audit levels
type Level string

const (
	LevelOff          Level = "off"
	LevelConnection   Level = "connection"
	LevelCommand      Level = "command"
	LevelCommandFull  Level = "command-full"
)

type Event struct {
	Timestamp string    `json:"timestamp"`
	Type      EventType `json:"type"`
	SessionID string    `json:"session_id"`
	Host      string    `json:"host,omitempty"`
	User      string    `json:"user,omitempty"`
	Command   string    `json:"command,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type Logger struct {
	path        string
	level       Level
	file        *os.File
	mu          sync.Mutex
	eventChan   chan Event
	done        chan struct{}
	wg          sync.WaitGroup
	batchSize   int
	batchWindow time.Duration
	isStdout    bool // stdout mode uses sync writes
}

func NewLogger(path string, level Level) (*Logger, error) {
	// Normalize level
	switch level {
	case LevelOff, LevelConnection, LevelCommand, LevelCommandFull:
	default:
		level = LevelCommand // default
	}

	// Empty path or off level disables audit logging
	if path == "" || level == LevelOff {
		log.Infow("Audit logging disabled")
		return &Logger{path: "", level: LevelOff, file: nil, eventChan: nil, done: nil}, nil
	}

	// "-" means stdout
	var file *os.File
	var isStdout bool
	if path == "-" {
		log.Infow("Audit logger initialized", "path", "stdout", "level", level)
		file = os.Stdout
		isStdout = true
	} else {
		// Ensure parent directory exists
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}

		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		file = f
		log.Infow("Audit logger initialized", "path", path, "level", level)
	}

	l := &Logger{
		path:        path,
		level:       level,
		file:        file,
		isStdout:    isStdout,
		eventChan:   make(chan Event, 1000), // buffer for async writes
		done:        make(chan struct{}),
		batchSize:   100,
		batchWindow: 100 * time.Millisecond,
	}

	// Start async writer goroutine only for file mode (not stdout)
	if !isStdout {
		l.wg.Add(1)
		go l.asyncWriter()
	}

	return l, nil
}

func (l *Logger) Close() error {
	// Signal async writer to stop
	if l.done != nil {
		close(l.done)
		l.wg.Wait()
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil && l.path != "-" {
		return l.file.Close()
	}
	return nil
}

// asyncWriter handles batched writes in a background goroutine
func (l *Logger) asyncWriter() {
	defer l.wg.Done()

	if l.file == nil {
		return
	}

	batch := make([][]byte, 0, l.batchSize)
	timer := time.NewTimer(l.batchWindow)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		l.mu.Lock()
		for _, data := range batch {
			if _, err := l.file.Write(data); err != nil {
				log.Debugw("Failed to write audit log", "error", err)
			}
		}
		if err := l.file.Sync(); err != nil {
			log.Debugw("Failed to sync audit log", "error", err)
		}
		l.mu.Unlock()
		batch = batch[:0]
	}

	for {
		select {
		case <-l.done:
			// Flush remaining events before shutdown
			flush()
			return
		case event := <-l.eventChan:
			event.Timestamp = time.Now().UTC().Format(time.RFC3339)
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			batch = append(batch, append(data, '\n'))
			if len(batch) >= l.batchSize {
				flush()
				timer.Reset(l.batchWindow)
			}
		case <-timer.C:
			flush()
		}
	}
}

func (l *Logger) writeEvent(event Event) error {
	// Skip if audit logging is disabled
	if l.file == nil {
		return nil
	}

	// stdout mode: sync writes for immediate output
	if l.isStdout {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		l.mu.Lock()
		_, err = l.file.Write(append(data, '\n'))
		l.mu.Unlock()
		return err
	}

	// file mode: non-blocking send to async writer
	select {
	case l.eventChan <- event:
		return nil
	default:
		// Channel full, log warning and drop event to avoid blocking
		log.Warnw("Audit log channel full, dropping event", "type", event.Type)
		return nil
	}
}

func (l *Logger) LogConnection(sessionID, host, user string) error {
	log.Infow("Audit: Connection", "session", sessionID, "host", host, "user", user)

	return l.writeEvent(Event{
		Type:      EventConnection,
		SessionID: sessionID,
		Host:      host,
		User:      user,
	})
}

func (l *Logger) LogDisconnection(sessionID, host string) error {
	log.Infow("Audit: Disconnection", "session", sessionID, "host", host)

	return l.writeEvent(Event{
		Type:      EventDisconnection,
		SessionID: sessionID,
		Host:      host,
	})
}

// LogCommand logs a command based on audit level:
// - command: only command name (first word)
// - command-full: full command with arguments
func (l *Logger) LogCommand(sessionID, host, command string) error {
	// Skip if level is connection-only or off
	if l.level == LevelConnection || l.level == LevelOff {
		return nil
	}

	// Strip arguments if level is "command"
	if l.level == LevelCommand {
		command = extractCommandName(command)
	}

	// Sanitize command to prevent log injection
	command = sanitizeForLog(command)

	return l.writeEvent(Event{
		Type:      EventCommand,
		SessionID: sessionID,
		Host:      host,
		Command:   command,
	})
}

// sanitizeForLog removes control characters that could be used for log injection
func sanitizeForLog(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		// Allow printable ASCII and common whitespace (space, tab)
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		} else if r == ' ' || r == '\t' {
			b.WriteRune(r)
		}
		// Replace other control chars with space to maintain readability
		// but prevent injection of newlines, etc.
	}
	return b.String()
}

func (l *Logger) LogError(sessionID, host, errMsg string) error {
	return l.writeEvent(Event{
		Type:      EventError,
		SessionID: sessionID,
		Host:      host,
		Error:     errMsg,
	})
}

// extractCommandName returns only the command name without arguments
func extractCommandName(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}

	// Handle sudo: "sudo cmd args" -> "sudo cmd"
	if strings.HasPrefix(cmd, "sudo ") {
		parts := strings.Fields(cmd)
		if len(parts) >= 2 {
			return parts[0] + " " + parts[1]
		}
		return parts[0]
	}

	// Handle pipes: "cmd1 | cmd2" -> "cmd1 | cmd2"
	// Just get first word of each command
	var result []string
	for _, part := range strings.Split(cmd, "|") {
		part = strings.TrimSpace(part)
		if part != "" {
			words := strings.Fields(part)
			if len(words) > 0 {
				result = append(result, words[0])
			}
		}
	}
	return strings.Join(result, " | ")
}

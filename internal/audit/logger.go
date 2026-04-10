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
	path       string
	level      Level
	file       *os.File
	mu         sync.Mutex
	maxRetries int
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
		return &Logger{path: "", level: LevelOff, file: nil, maxRetries: 0}, nil
	}

	// "-" means stdout
	var file *os.File
	if path == "-" {
		log.Infow("Audit logger initialized", "path", "stdout", "level", level)
		file = os.Stdout
	} else {
		// Ensure parent directory exists
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}

		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		file = f
		log.Infow("Audit logger initialized", "path", path, "level", level)
	}

	return &Logger{
		path:       path,
		level:      level,
		file:       file,
		maxRetries: 3,
	}, nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil && l.path != "-" {
		return l.file.Close()
	}
	return nil
}

func (l *Logger) writeEvent(event Event) error {
	// Skip if audit logging is disabled
	if l.file == nil {
		return nil
	}

	event.Timestamp = time.Now().UTC().Format(time.RFC3339)

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	var lastErr error
	for i := 0; i < l.maxRetries; i++ {
		_, err := l.file.Write(append(data, '\n'))
		if err == nil {
			if syncErr := l.file.Sync(); syncErr != nil {
				log.Debugw("Failed to sync audit log", "error", syncErr)
			}
			log.Debugw("Audit event logged", "type", event.Type)
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(100*(i+1)) * time.Millisecond)
	}

	return lastErr
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

	return l.writeEvent(Event{
		Type:      EventCommand,
		SessionID: sessionID,
		Host:      host,
		Command:   command,
	})
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

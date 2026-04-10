package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/fimreal/goutils/ezap"
)

type EventType string

const (
	EventConnection    EventType = "connection"
	EventDisconnection EventType = "disconnection"
	EventError         EventType = "error"
)

type Event struct {
	Timestamp string    `json:"timestamp"`
	Type      EventType `json:"type"`
	SessionID string    `json:"session_id"`
	Host      string    `json:"host,omitempty"`
	User      string    `json:"user,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type Logger struct {
	path       string
	file       *os.File
	mu         sync.Mutex
	maxRetries int
}

func NewLogger(path string) (*Logger, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	log.Infow("Audit logger initialized", "path", path)

	return &Logger{
		path:       path,
		file:       file,
		maxRetries: 3,
	}, nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *Logger) writeEvent(event Event) error {
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

func (l *Logger) LogError(sessionID, host, errMsg string) error {
	return l.writeEvent(Event{
		Type:      EventError,
		SessionID: sessionID,
		Host:      host,
		Error:     errMsg,
	})
}

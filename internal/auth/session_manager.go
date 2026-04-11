package auth

import (
	"sync"
)

// SessionManager tracks active sessions per token
type SessionManager struct {
	sessions    map[string]int // token -> session count
	mu          sync.RWMutex
	maxSessions int
}

// NewSessionManager creates a new session manager
func NewSessionManager(maxSessions int) *SessionManager {
	return &SessionManager{
		sessions:    make(map[string]int),
		maxSessions: maxSessions,
	}
}

// CanCreateSession checks if a new session can be created for the token
func (sm *SessionManager) CanCreateSession(tokenID string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := sm.sessions[tokenID]
	return count < sm.maxSessions
}

// AddSession registers a new session for the token
func (sm *SessionManager) AddSession(tokenID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.sessions[tokenID]++
}

// RemoveSession unregisters a session for the token
func (sm *SessionManager) RemoveSession(tokenID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.sessions[tokenID] > 0 {
		sm.sessions[tokenID]--
		if sm.sessions[tokenID] == 0 {
			delete(sm.sessions, tokenID)
		}
	}
}

// GetSessionCount returns the number of active sessions for a token
func (sm *SessionManager) GetSessionCount(tokenID string) int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.sessions[tokenID]
}

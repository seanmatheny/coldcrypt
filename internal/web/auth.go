package web

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const sessionTTL = 24 * time.Hour

type session struct {
	createdAt time.Time
}

// SessionStore manages in-memory sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]session
}

// NewSessionStore creates a new session store.
func NewSessionStore() *SessionStore {
	s := &SessionStore{
		sessions: make(map[string]session),
	}
	go s.cleanup()
	return s
}

// CreateSession creates a new session and returns the session ID (64-char hex string).
func (s *SessionStore) CreateSession() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)

	s.mu.Lock()
	s.sessions[id] = session{createdAt: time.Now()}
	s.mu.Unlock()
	return id
}

// ValidateSession checks if a session ID is valid and not expired.
func (s *SessionStore) ValidateSession(sessionID string) bool {
	s.mu.RLock()
	sess, ok := s.sessions[sessionID]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	return time.Since(sess.createdAt) < sessionTTL
}

// DeleteSession removes a session.
func (s *SessionStore) DeleteSession(sessionID string) {
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()
}

// cleanup removes expired sessions periodically.
func (s *SessionStore) cleanup() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		for id, sess := range s.sessions {
			if time.Since(sess.createdAt) >= sessionTTL {
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

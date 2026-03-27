package session

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileBackedSessionStore wraps InMemorySessionStore with file-based persistence.
// Sessions are held in memory for performance and periodically flushed to disk.
type FileBackedSessionStore struct {
	*InMemorySessionStore
	filePath string
	crypto   sessionCrypto
	saveMu   sync.Mutex
}

// sessionCrypto is a minimal interface matching clients.StorageCrypto for encryption.
type sessionCrypto interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

// NewFileBackedSessionStore creates a new file-backed session store.
// If crypto is nil, data is stored unencrypted.
func NewFileBackedSessionStore(filePath string, crypto sessionCrypto) *FileBackedSessionStore {
	store := &FileBackedSessionStore{
		InMemorySessionStore: NewInMemorySessionStore(),
		filePath:             filePath,
		crypto:               crypto,
	}

	if err := store.loadFromFile(); err != nil {
		log.Printf("Warning: Failed to load sessions from file: %v", err)
	}

	return store
}

// Set overrides the in-memory Set to also persist.
func (s *FileBackedSessionStore) Set(sessionID, targetAddress string) error {
	if err := s.InMemorySessionStore.Set(sessionID, targetAddress); err != nil {
		return err
	}
	return s.persist()
}

// SetWithDetails overrides to also persist.
func (s *FileBackedSessionStore) SetWithDetails(sessionID, adapterName, targetAddress, connectionType string) error {
	if err := s.InMemorySessionStore.SetWithDetails(sessionID, adapterName, targetAddress, connectionType); err != nil {
		return err
	}
	return s.persist()
}

// Delete overrides to also persist.
func (s *FileBackedSessionStore) Delete(sessionID string) error {
	if err := s.InMemorySessionStore.Delete(sessionID); err != nil {
		return err
	}
	return s.persist()
}

// DeleteByAdapter overrides to also persist.
func (s *FileBackedSessionStore) DeleteByAdapter(adapterName string) error {
	if err := s.InMemorySessionStore.DeleteByAdapter(adapterName); err != nil {
		return err
	}
	return s.persist()
}

// SetTokenInfo overrides to also persist.
func (s *FileBackedSessionStore) SetTokenInfo(sessionID string, tokenInfo *TokenInfo) error {
	if err := s.InMemorySessionStore.SetTokenInfo(sessionID, tokenInfo); err != nil {
		return err
	}
	return s.persist()
}

// RefreshToken overrides to also persist.
func (s *FileBackedSessionStore) RefreshToken(sessionID, newAccessToken string, expiresAt time.Time) error {
	if err := s.InMemorySessionStore.RefreshToken(sessionID, newAccessToken, expiresAt); err != nil {
		return err
	}
	return s.persist()
}

// SetAuthorizationInfo overrides to also persist.
func (s *FileBackedSessionStore) SetAuthorizationInfo(sessionID string, authInfo *AuthorizationInfo) error {
	if err := s.InMemorySessionStore.SetAuthorizationInfo(sessionID, authInfo); err != nil {
		return err
	}
	return s.persist()
}

// CleanupExpired overrides to also persist after cleanup.
func (s *FileBackedSessionStore) CleanupExpired(maxAge time.Duration) error {
	if err := s.InMemorySessionStore.CleanupExpired(maxAge); err != nil {
		return err
	}
	return s.persist()
}

// persist writes the current session state to disk.
func (s *FileBackedSessionStore) persist() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mutex.RLock()
	sessions := make([]SessionDetails, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.mutex.RUnlock()

	data, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sessions: %w", err)
	}

	if s.crypto != nil {
		data, err = s.crypto.Encrypt(data)
		if err != nil {
			return fmt.Errorf("failed to encrypt sessions: %w", err)
		}
	}

	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}

	tempFile := s.filePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	if err := os.Rename(tempFile, s.filePath); err != nil {
		return fmt.Errorf("failed to rename session file: %w", err)
	}

	return nil
}

// loadFromFile restores sessions from the persisted JSON file.
func (s *FileBackedSessionStore) loadFromFile() error {
	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("failed to read session file: %w", err)
	}

	if len(data) == 0 {
		return nil
	}

	if s.crypto != nil {
		data, err = s.crypto.Decrypt(data)
		if err != nil {
			return fmt.Errorf("failed to decrypt session file: %w", err)
		}
	}

	var sessions []SessionDetails
	if err := json.Unmarshal(data, &sessions); err != nil {
		return fmt.Errorf("failed to parse session file: %w", err)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, session := range sessions {
		s.sessions[session.SessionID] = session
	}

	return nil
}

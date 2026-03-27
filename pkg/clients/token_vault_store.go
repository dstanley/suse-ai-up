package clients

import (
	"fmt"
	"sync"

	"suse-ai-up/pkg/models"
)

// TokenVaultStore defines the interface for downstream token storage.
type TokenVaultStore interface {
	Get(userID, adapterName string) (*models.TokenVaultEntry, error)
	Set(entry models.TokenVaultEntry) error
	Delete(userID, adapterName string) error
	List(userID string) ([]models.TokenVaultEntry, error)
}

// vaultKey builds a composite key from UserID and AdapterName.
func vaultKey(userID, adapterName string) string {
	return userID + "|" + adapterName
}

// InMemoryTokenVaultStore implements TokenVaultStore with in-memory-only storage.
// Exchanged downstream tokens are never persisted to disk — on process restart,
// users re-authenticate and tokens are re-exchanged. This is intentional:
// these are borrowed credentials for external services and should not survive
// node crashes or pod evictions.
type InMemoryTokenVaultStore struct {
	entries map[string]models.TokenVaultEntry
	mu      sync.RWMutex
}

// NewInMemoryTokenVaultStore creates a new in-memory token vault store.
func NewInMemoryTokenVaultStore() *InMemoryTokenVaultStore {
	return &InMemoryTokenVaultStore{
		entries: make(map[string]models.TokenVaultEntry),
	}
}

// Get retrieves a token vault entry by UserID and AdapterName.
func (s *InMemoryTokenVaultStore) Get(userID, adapterName string) (*models.TokenVaultEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.entries[vaultKey(userID, adapterName)]
	if !exists {
		return nil, fmt.Errorf("token vault entry not found for user %s, adapter %s", userID, adapterName)
	}

	copy := entry
	return &copy, nil
}

// Set stores or updates a token vault entry.
func (s *InMemoryTokenVaultStore) Set(entry models.TokenVaultEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[vaultKey(entry.UserID, entry.AdapterName)] = entry
	return nil
}

// Delete removes a token vault entry.
func (s *InMemoryTokenVaultStore) Delete(userID, adapterName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := vaultKey(userID, adapterName)
	if _, exists := s.entries[key]; !exists {
		return fmt.Errorf("token vault entry not found for user %s, adapter %s", userID, adapterName)
	}

	delete(s.entries, key)
	return nil
}

// List returns all token vault entries for a given user.
func (s *InMemoryTokenVaultStore) List(userID string) ([]models.TokenVaultEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []models.TokenVaultEntry
	for _, entry := range s.entries {
		if entry.UserID == userID {
			result = append(result, entry)
		}
	}
	return result, nil
}

package clients

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"suse-ai-up/pkg/models"
)

// OAuthClientStore defines the interface for OAuth client registration storage.
// Implementations can be file-based, database-backed, or use external stores like Redis.
type OAuthClientStore interface {
	Create(client models.OAuthRegisteredClient) error
	Get(clientID string) (*models.OAuthRegisteredClient, error)
	List() ([]models.OAuthRegisteredClient, error)
	Delete(clientID string) error
	Count() (int, error)
	UpdateActivity(clientID string, at time.Time) error
	DeleteExpiredBefore(cutoff time.Time) (int, error)
}

// FileOAuthClientStore implements OAuthClientStore with encrypted file-based persistence.
type FileOAuthClientStore struct {
	filePath string
	clients  map[string]models.OAuthRegisteredClient
	mu       sync.RWMutex
	crypto   *StorageCrypto
}

// NewFileOAuthClientStore creates a new file-based OAuth client store.
func NewFileOAuthClientStore(filePath string, crypto *StorageCrypto) *FileOAuthClientStore {
	store := &FileOAuthClientStore{
		filePath: filePath,
		clients:  make(map[string]models.OAuthRegisteredClient),
		crypto:   crypto,
	}

	if err := store.loadFromFile(); err != nil {
		fmt.Printf("Warning: Failed to load OAuth clients from file: %v\n", err)
	}

	return store
}

// Create stores a new OAuth client.
func (s *FileOAuthClientStore) Create(client models.OAuthRegisteredClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[client.ClientID]; exists {
		return fmt.Errorf("client with ID %s already exists", client.ClientID)
	}

	s.clients[client.ClientID] = client
	return s.saveToFile()
}

// Get retrieves an OAuth client by client_id.
func (s *FileOAuthClientStore) Get(clientID string) (*models.OAuthRegisteredClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("client with ID %s not found", clientID)
	}

	copy := client
	return &copy, nil
}

// List returns all registered OAuth clients.
func (s *FileOAuthClientStore) List() ([]models.OAuthRegisteredClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]models.OAuthRegisteredClient, 0, len(s.clients))
	for _, client := range s.clients {
		result = append(result, client)
	}
	return result, nil
}

// Delete removes an OAuth client by client_id.
func (s *FileOAuthClientStore) Delete(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[clientID]; !exists {
		return fmt.Errorf("client with ID %s not found", clientID)
	}

	delete(s.clients, clientID)
	return s.saveToFile()
}

// Count returns the number of registered clients.
func (s *FileOAuthClientStore) Count() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients), nil
}

// UpdateActivity updates the last activity timestamp for a client.
func (s *FileOAuthClientStore) UpdateActivity(clientID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	client, exists := s.clients[clientID]
	if !exists {
		return fmt.Errorf("client with ID %s not found", clientID)
	}

	client.LastActivityAt = at
	s.clients[clientID] = client
	return s.saveToFile()
}

// DeleteExpiredBefore removes all clients whose LastActivityAt is before the cutoff.
// Clients with a zero LastActivityAt use CreatedAt instead.
// Returns the number of clients removed.
func (s *FileOAuthClientStore) DeleteExpiredBefore(cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var expired []string
	for id, client := range s.clients {
		activityTime := client.LastActivityAt
		if activityTime.IsZero() {
			activityTime = client.CreatedAt
		}
		if activityTime.Before(cutoff) {
			expired = append(expired, id)
		}
	}

	if len(expired) == 0 {
		return 0, nil
	}

	for _, id := range expired {
		delete(s.clients, id)
	}

	if err := s.saveToFile(); err != nil {
		return 0, err
	}
	return len(expired), nil
}

func (s *FileOAuthClientStore) loadFromFile() error {
	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("failed to read OAuth clients file: %w", err)
	}

	if len(data) == 0 {
		return nil
	}

	if s.crypto != nil {
		data, err = s.crypto.Decrypt(data)
		if err != nil {
			return fmt.Errorf("failed to decrypt OAuth clients file: %w", err)
		}
	}

	var clients []models.OAuthRegisteredClient
	if err := json.Unmarshal(data, &clients); err != nil {
		return fmt.Errorf("failed to parse OAuth clients file: %w", err)
	}

	for _, client := range clients {
		s.clients[client.ClientID] = client
	}
	return nil
}

func (s *FileOAuthClientStore) saveToFile() error {
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create OAuth clients directory: %w", err)
	}

	clients := make([]models.OAuthRegisteredClient, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}

	data, err := json.MarshalIndent(clients, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal OAuth clients: %w", err)
	}

	if s.crypto != nil {
		data, err = s.crypto.Encrypt(data)
		if err != nil {
			return fmt.Errorf("failed to encrypt OAuth clients: %w", err)
		}
	}

	tempFile := s.filePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write OAuth clients file: %w", err)
	}

	if err := os.Rename(tempFile, s.filePath); err != nil {
		return fmt.Errorf("failed to rename OAuth clients file: %w", err)
	}

	return nil
}

package clients

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"suse-ai-up/pkg/models"
)

// OAuthClientStore defines the interface for OAuth client registration storage.
type OAuthClientStore interface {
	Create(client models.OAuthRegisteredClient) error
	Get(clientID string) (*models.OAuthRegisteredClient, error)
	List() ([]models.OAuthRegisteredClient, error)
	Delete(clientID string) error
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

package clients

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"suse-ai-up/pkg/models"
)

// AuthPolicyStore defines the interface for authorization policy storage.
type AuthPolicyStore interface {
	Create(policy models.AuthorizationPolicy) error
	Get(policyID string) (*models.AuthorizationPolicy, error)
	Update(policy models.AuthorizationPolicy) error
	Delete(policyID string) error
	List() ([]models.AuthorizationPolicy, error)
	ListByAdapter(adapterName string) ([]models.AuthorizationPolicy, error)
	ListByAdapterAndTool(adapterName, toolName string) ([]models.AuthorizationPolicy, error)
}

// FileAuthPolicyStore implements AuthPolicyStore with file-based JSON persistence.
type FileAuthPolicyStore struct {
	filePath string
	policies map[string]models.AuthorizationPolicy
	mu       sync.RWMutex
	crypto   *StorageCrypto
}

// NewFileAuthPolicyStore creates a new file-based auth policy store.
func NewFileAuthPolicyStore(filePath string, crypto *StorageCrypto) *FileAuthPolicyStore {
	store := &FileAuthPolicyStore{
		filePath: filePath,
		policies: make(map[string]models.AuthorizationPolicy),
		crypto:   crypto,
	}

	if err := store.loadFromFile(); err != nil {
		fmt.Printf("Warning: Failed to load auth policies from file: %v\n", err)
	}

	return store
}

// Create stores a new authorization policy.
func (s *FileAuthPolicyStore) Create(policy models.AuthorizationPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.policies[policy.PolicyID]; exists {
		return fmt.Errorf("policy with ID %s already exists", policy.PolicyID)
	}

	s.policies[policy.PolicyID] = policy
	return s.saveToFile()
}

// Get retrieves a policy by ID.
func (s *FileAuthPolicyStore) Get(policyID string) (*models.AuthorizationPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policy, exists := s.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy with ID %s not found", policyID)
	}

	copy := policy
	return &copy, nil
}

// Update replaces an existing policy.
func (s *FileAuthPolicyStore) Update(policy models.AuthorizationPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.policies[policy.PolicyID]; !exists {
		return fmt.Errorf("policy with ID %s not found", policy.PolicyID)
	}

	s.policies[policy.PolicyID] = policy
	return s.saveToFile()
}

// Delete removes a policy by ID.
func (s *FileAuthPolicyStore) Delete(policyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.policies[policyID]; !exists {
		return fmt.Errorf("policy with ID %s not found", policyID)
	}

	delete(s.policies, policyID)
	return s.saveToFile()
}

// List returns all policies sorted by priority (highest first).
func (s *FileAuthPolicyStore) List() ([]models.AuthorizationPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]models.AuthorizationPolicy, 0, len(s.policies))
	for _, policy := range s.policies {
		result = append(result, policy)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority > result[j].Priority
	})
	return result, nil
}

// ListByAdapter returns all policies for a given adapter, sorted by priority.
func (s *FileAuthPolicyStore) ListByAdapter(adapterName string) ([]models.AuthorizationPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []models.AuthorizationPolicy
	for _, policy := range s.policies {
		if policy.AdapterName == adapterName || policy.AdapterName == "*" {
			result = append(result, policy)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority > result[j].Priority
	})
	return result, nil
}

// ListByAdapterAndTool returns policies matching a specific adapter and tool, sorted by priority.
func (s *FileAuthPolicyStore) ListByAdapterAndTool(adapterName, toolName string) ([]models.AuthorizationPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []models.AuthorizationPolicy
	for _, policy := range s.policies {
		adapterMatch := policy.AdapterName == adapterName || policy.AdapterName == "*"
		toolMatch := policy.ToolName == toolName || policy.ToolName == "*"
		if adapterMatch && toolMatch {
			result = append(result, policy)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority > result[j].Priority
	})
	return result, nil
}

func (s *FileAuthPolicyStore) loadFromFile() error {
	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("failed to read auth policies file: %w", err)
	}

	if len(data) == 0 {
		return nil
	}

	if s.crypto != nil {
		data, err = s.crypto.Decrypt(data)
		if err != nil {
			return fmt.Errorf("failed to decrypt auth policies file: %w", err)
		}
	}

	var policies []models.AuthorizationPolicy
	if err := json.Unmarshal(data, &policies); err != nil {
		return fmt.Errorf("failed to parse auth policies file: %w", err)
	}

	for _, policy := range policies {
		s.policies[policy.PolicyID] = policy
	}
	return nil
}

func (s *FileAuthPolicyStore) saveToFile() error {
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create auth policies directory: %w", err)
	}

	policies := make([]models.AuthorizationPolicy, 0, len(s.policies))
	for _, policy := range s.policies {
		policies = append(policies, policy)
	}

	data, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal auth policies: %w", err)
	}

	if s.crypto != nil {
		data, err = s.crypto.Encrypt(data)
		if err != nil {
			return fmt.Errorf("failed to encrypt auth policies: %w", err)
		}
	}

	tempFile := s.filePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write auth policies file: %w", err)
	}

	if err := os.Rename(tempFile, s.filePath); err != nil {
		return fmt.Errorf("failed to rename auth policies file: %w", err)
	}

	return nil
}

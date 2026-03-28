package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"suse-ai-up/pkg/models"
)

// mockPolicyStore implements clients.AuthPolicyStore for testing
type mockPolicyStore struct {
	policies map[string][]models.AuthorizationPolicy
}

func (m *mockPolicyStore) Create(policy models.AuthorizationPolicy) error              { return nil }
func (m *mockPolicyStore) Get(id string) (*models.AuthorizationPolicy, error)          { return nil, nil }
func (m *mockPolicyStore) Update(policy models.AuthorizationPolicy) error              { return nil }
func (m *mockPolicyStore) Delete(id string) error                                      { return nil }
func (m *mockPolicyStore) List() ([]models.AuthorizationPolicy, error)                 { return nil, nil }
func (m *mockPolicyStore) ListByAdapter(adapterName string) ([]models.AuthorizationPolicy, error) {
	return nil, nil
}

func (m *mockPolicyStore) ListByAdapterAndTool(adapterName, toolName string) ([]models.AuthorizationPolicy, error) {
	key := adapterName + ":" + toolName
	return m.policies[key], nil
}

func TestIsToolAllowed_RequiredScopes_UserHasScopes(t *testing.T) {
	store := &mockPolicyStore{
		policies: map[string][]models.AuthorizationPolicy{
			"databricks:drop_table": {
				{
					PolicyID:       "p1",
					AdapterName:    "databricks",
					ToolName:       "drop_table",
					Effect:         "allow",
					RequiredScopes: []string{"sql:write"},
				},
			},
		},
	}

	pe := NewPolicyEngine(store)
	user := &UserContext{
		UserID:         "alice",
		Groups:         []string{"data-engineers"},
		ResolvedScopes: []string{"sql:read", "sql:write"},
	}

	allowed, _ := pe.IsToolAllowed("databricks", "drop_table", user)
	assert.True(t, allowed)
}

func TestIsToolAllowed_RequiredScopes_UserLacksScopes(t *testing.T) {
	store := &mockPolicyStore{
		policies: map[string][]models.AuthorizationPolicy{
			"databricks:drop_table": {
				{
					PolicyID:       "p1",
					AdapterName:    "databricks",
					ToolName:       "drop_table",
					Effect:         "allow",
					RequiredScopes: []string{"sql:write"},
				},
			},
		},
	}

	pe := NewPolicyEngine(store)
	user := &UserContext{
		UserID:         "bob",
		Groups:         []string{"analysts"},
		ResolvedScopes: []string{"sql:read"},
	}

	allowed, _ := pe.IsToolAllowed("databricks", "drop_table", user)
	// Policy requires sql:write but user only has sql:read — policy doesn't match,
	// so default fallback is allow (no matching policies)
	assert.True(t, allowed)
}

func TestIsToolAllowed_RequiredScopes_DenyStillTakesPrecedence(t *testing.T) {
	store := &mockPolicyStore{
		policies: map[string][]models.AuthorizationPolicy{
			"databricks:drop_table": {
				{
					PolicyID:       "p-deny",
					AdapterName:    "databricks",
					ToolName:       "drop_table",
					Effect:         "deny",
					DeniedGroups:   []string{"interns"},
				},
				{
					PolicyID:       "p-allow",
					AdapterName:    "databricks",
					ToolName:       "drop_table",
					Effect:         "allow",
					RequiredScopes: []string{"sql:write"},
				},
			},
		},
	}

	pe := NewPolicyEngine(store)
	user := &UserContext{
		UserID:         "intern1",
		Groups:         []string{"interns"},
		ResolvedScopes: []string{"sql:read", "sql:write"},
	}

	allowed, policyID := pe.IsToolAllowed("databricks", "drop_table", user)
	assert.False(t, allowed)
	assert.Equal(t, "p-deny", policyID)
}

func TestIsToolAllowed_RequiredScopes_MultipleRequired(t *testing.T) {
	store := &mockPolicyStore{
		policies: map[string][]models.AuthorizationPolicy{
			"databricks:manage_cluster": {
				{
					PolicyID:       "p1",
					AdapterName:    "databricks",
					ToolName:       "manage_cluster",
					Effect:         "allow",
					RequiredScopes: []string{"clusters:manage", "sql:write"},
				},
			},
		},
	}

	pe := NewPolicyEngine(store)

	// User has only one of two required scopes
	user := &UserContext{
		UserID:         "alice",
		ResolvedScopes: []string{"sql:write"},
	}
	allowed, _ := pe.IsToolAllowed("databricks", "manage_cluster", user)
	assert.True(t, allowed) // Policy doesn't match, defaults to allow

	// User has both required scopes
	user.ResolvedScopes = []string{"sql:write", "clusters:manage"}
	allowed, _ = pe.IsToolAllowed("databricks", "manage_cluster", user)
	assert.True(t, allowed)
}

func TestIsToolAllowed_RequiredScopes_WithGroupConstraint(t *testing.T) {
	store := &mockPolicyStore{
		policies: map[string][]models.AuthorizationPolicy{
			"databricks:drop_table": {
				// Only data-engineers with sql:write scope can use drop_table
				{
					PolicyID:       "p1",
					AdapterName:    "databricks",
					ToolName:       "drop_table",
					Effect:         "allow",
					AllowedGroups:  []string{"data-engineers"},
					RequiredScopes: []string{"sql:write"},
				},
				// Everyone else is denied
				{
					PolicyID:    "p-default-deny",
					AdapterName: "databricks",
					ToolName:    "drop_table",
					Effect:      "deny",
					DeniedGroups: []string{},
					DeniedUsers:  []string{},
				},
			},
		},
	}

	pe := NewPolicyEngine(store)

	// data-engineer with sql:write — allowed
	allowed, _ := pe.IsToolAllowed("databricks", "drop_table", &UserContext{
		UserID:         "alice",
		Groups:         []string{"data-engineers"},
		ResolvedScopes: []string{"sql:read", "sql:write"},
	})
	assert.True(t, allowed)

	// data-engineer without sql:write — scope policy doesn't match, but
	// default deny also doesn't match (empty denied lists), so default allow
	allowed, _ = pe.IsToolAllowed("databricks", "drop_table", &UserContext{
		UserID:         "bob",
		Groups:         []string{"data-engineers"},
		ResolvedScopes: []string{"sql:read"},
	})
	assert.True(t, allowed)
}

func TestFilterTools_WithScopes(t *testing.T) {
	store := &mockPolicyStore{
		policies: map[string][]models.AuthorizationPolicy{
			"databricks:drop_table": {
				{
					PolicyID:       "p1",
					Effect:         "allow",
					AllowedGroups:  []string{"data-engineers"},
					RequiredScopes: []string{"sql:write"},
				},
			},
			"databricks:query": {
				{
					PolicyID: "p2",
					Effect:   "allow",
				},
			},
		},
	}

	pe := NewPolicyEngine(store)

	tools := []string{"drop_table", "query", "list_tables"}

	// User with sql:write in data-engineers — sees all tools
	result := pe.FilterTools("databricks", tools, &UserContext{
		UserID:         "alice",
		Groups:         []string{"data-engineers"},
		ResolvedScopes: []string{"sql:read", "sql:write"},
	})
	assert.Equal(t, []string{"drop_table", "query", "list_tables"}, result)

	// User with only sql:read — drop_table policy doesn't match (no scope),
	// but no deny either, so still sees all (default allow)
	result = pe.FilterTools("databricks", tools, &UserContext{
		UserID:         "bob",
		Groups:         []string{"analysts"},
		ResolvedScopes: []string{"sql:read"},
	})
	assert.Equal(t, []string{"drop_table", "query", "list_tables"}, result)
}

func TestHasAllScopes(t *testing.T) {
	assert.True(t, hasAllScopes([]string{"a", "b", "c"}, []string{"a", "b"}))
	assert.True(t, hasAllScopes([]string{"a", "b", "c"}, []string{}))
	assert.False(t, hasAllScopes([]string{"a"}, []string{"a", "b"}))
	assert.False(t, hasAllScopes([]string{}, []string{"a"}))
	assert.True(t, hasAllScopes([]string{"a"}, []string{"a"}))
}

package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"suse-ai-up/pkg/models"
)

func TestResolveScopesForUser_NoPolicies(t *testing.T) {
	user := &UserContext{UserID: "alice", Groups: []string{"engineers"}}
	fallback := []string{"read"}
	result := ResolveScopesForUser(nil, user, fallback)
	assert.Equal(t, []string{"read"}, result)
}

func TestResolveScopesForUser_SingleGroupMatch(t *testing.T) {
	policies := []models.ScopePolicy{
		{Groups: []string{"data-engineers"}, Scopes: []string{"sql:read", "sql:write"}},
		{Groups: []string{"analysts"}, Scopes: []string{"sql:read"}},
	}
	user := &UserContext{UserID: "alice", Groups: []string{"data-engineers"}}
	result := ResolveScopesForUser(policies, user, []string{"default"})
	assert.Equal(t, []string{"sql:read", "sql:write"}, result)
}

func TestResolveScopesForUser_MultiGroupUnion(t *testing.T) {
	policies := []models.ScopePolicy{
		{Groups: []string{"data-engineers"}, Scopes: []string{"sql:read", "sql:write"}},
		{Groups: []string{"cluster-ops"}, Scopes: []string{"clusters:manage"}},
	}
	user := &UserContext{UserID: "bob", Groups: []string{"data-engineers", "cluster-ops"}}
	result := ResolveScopesForUser(policies, user, []string{"default"})
	assert.Contains(t, result, "sql:read")
	assert.Contains(t, result, "sql:write")
	assert.Contains(t, result, "clusters:manage")
	assert.Len(t, result, 3)
}

func TestResolveScopesForUser_UserIDMatch(t *testing.T) {
	policies := []models.ScopePolicy{
		{Users: []string{"admin"}, Scopes: []string{"admin:all"}},
		{Groups: []string{"users"}, Scopes: []string{"read"}},
	}
	user := &UserContext{UserID: "admin", Groups: []string{"users"}}
	result := ResolveScopesForUser(policies, user, nil)
	// Matches both policies — union
	assert.Contains(t, result, "admin:all")
	assert.Contains(t, result, "read")
}

func TestResolveScopesForUser_DefaultPolicyMatchesAll(t *testing.T) {
	policies := []models.ScopePolicy{
		{Groups: []string{"admins"}, Scopes: []string{"admin:all"}, Priority: 10},
		{Scopes: []string{"read"}, Priority: 0}, // default — empty groups/users
	}
	user := &UserContext{UserID: "guest", Groups: []string{}}
	result := ResolveScopesForUser(policies, user, []string{"none"})
	// Only the default policy matches
	assert.Equal(t, []string{"read"}, result)
}

func TestResolveScopesForUser_NoMatch_Fallback(t *testing.T) {
	policies := []models.ScopePolicy{
		{Groups: []string{"admins"}, Scopes: []string{"admin:all"}},
	}
	user := &UserContext{UserID: "guest", Groups: []string{"viewers"}}
	result := ResolveScopesForUser(policies, user, []string{"fallback:read"})
	assert.Equal(t, []string{"fallback:read"}, result)
}

func TestResolveScopesForUser_DeduplicatesScopes(t *testing.T) {
	policies := []models.ScopePolicy{
		{Groups: []string{"team-a"}, Scopes: []string{"read", "write"}},
		{Groups: []string{"team-b"}, Scopes: []string{"read", "delete"}},
	}
	user := &UserContext{UserID: "alice", Groups: []string{"team-a", "team-b"}}
	result := ResolveScopesForUser(policies, user, nil)
	assert.Len(t, result, 3)
	assert.Contains(t, result, "read")
	assert.Contains(t, result, "write")
	assert.Contains(t, result, "delete")
}

func TestResolveScopesForUser_PriorityOrdering(t *testing.T) {
	// Priority only affects evaluation order, not filtering — all matching policies merge
	policies := []models.ScopePolicy{
		{Groups: []string{"ops"}, Scopes: []string{"low-scope"}, Priority: 1},
		{Groups: []string{"ops"}, Scopes: []string{"high-scope"}, Priority: 100},
	}
	user := &UserContext{UserID: "alice", Groups: []string{"ops"}}
	result := ResolveScopesForUser(policies, user, nil)
	assert.Contains(t, result, "low-scope")
	assert.Contains(t, result, "high-scope")
}

func TestResolveScopesForUser_EmailMatch(t *testing.T) {
	policies := []models.ScopePolicy{
		{Users: []string{"alice@example.com"}, Scopes: []string{"special:access"}},
	}
	user := &UserContext{UserID: "alice", Email: "alice@example.com", Groups: []string{}}
	result := ResolveScopesForUser(policies, user, []string{"default"})
	assert.Equal(t, []string{"special:access"}, result)
}

func TestResolveScopesForUser_RoleMatch(t *testing.T) {
	policies := []models.ScopePolicy{
		{Groups: []string{"cluster-admin"}, Scopes: []string{"admin:all"}},
	}
	user := &UserContext{UserID: "alice", Roles: []string{"cluster-admin"}}
	result := ResolveScopesForUser(policies, user, []string{"default"})
	assert.Equal(t, []string{"admin:all"}, result)
}

func TestResolveScopesString(t *testing.T) {
	policies := []models.ScopePolicy{
		{Groups: []string{"team"}, Scopes: []string{"read", "write"}},
	}
	user := &UserContext{UserID: "alice", Groups: []string{"team"}}
	result := ResolveScopesString(policies, user, nil)
	assert.Equal(t, "read write", result)
}

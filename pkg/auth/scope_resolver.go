package auth

import (
	"sort"
	"strings"

	"suse-ai-up/pkg/models"
)

// ResolveScopesForUser evaluates scope policies against a user's identity and returns
// the appropriate backend scopes. Resolution rules:
//  1. Policies are evaluated in priority order (highest first)
//  2. All matching policies' scopes are merged (union)
//  3. If no policies match, fallbackScopes are returned
//  4. A policy matches if the user is in any of its Groups or Users lists
//  5. Empty Groups and Users on a policy means it matches all users (default policy)
func ResolveScopesForUser(policies []models.ScopePolicy, user *UserContext, fallbackScopes []string) []string {
	if len(policies) == 0 {
		return fallbackScopes
	}

	// Sort by priority descending
	sorted := make([]models.ScopePolicy, len(policies))
	copy(sorted, policies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})

	// Collect scopes from all matching policies (union)
	scopeSet := make(map[string]struct{})
	matched := false

	for _, policy := range sorted {
		if scopePolicyMatchesUser(policy, user) {
			matched = true
			for _, s := range policy.Scopes {
				scopeSet[s] = struct{}{}
			}
		}
	}

	if !matched {
		return fallbackScopes
	}

	scopes := make([]string, 0, len(scopeSet))
	for s := range scopeSet {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)
	return scopes
}

// ResolveScopesString is a convenience wrapper that returns scopes as a space-separated string.
func ResolveScopesString(policies []models.ScopePolicy, user *UserContext, fallbackScopes []string) string {
	scopes := ResolveScopesForUser(policies, user, fallbackScopes)
	return strings.Join(scopes, " ")
}

// ResolveUserScopes creates a copy of the user context with backend-specific resolved scopes
// for a given adapter auth config. This allows tool authorization policies to check
// required_scopes against the user's backend-specific scopes.
func ResolveUserScopes(uc *UserContext, authConfig *models.AdapterAuthConfig) *UserContext {
	scopeCtx := &UserContext{
		UserID:   uc.UserID,
		Username: uc.Username,
		Email:    uc.Email,
		Groups:   uc.Groups,
		Roles:    uc.Roles,
	}

	if authConfig == nil {
		return scopeCtx
	}

	if authConfig.TokenExchange != nil && len(authConfig.TokenExchange.ScopePolicies) > 0 {
		scopeCtx.ResolvedScopes = ResolveScopesForUser(
			authConfig.TokenExchange.ScopePolicies, uc,
			authConfig.TokenExchange.Scopes,
		)
		return scopeCtx
	}

	if authConfig.ServiceAccount != nil && len(authConfig.ServiceAccount.ScopePolicies) > 0 {
		scopeCtx.ResolvedScopes = ResolveScopesForUser(
			authConfig.ServiceAccount.ScopePolicies, uc, nil,
		)
		return scopeCtx
	}

	if authConfig.TokenExchange != nil {
		scopeCtx.ResolvedScopes = authConfig.TokenExchange.Scopes
	}

	return scopeCtx
}

// scopePolicyMatchesUser checks if a scope policy applies to the given user.
func scopePolicyMatchesUser(policy models.ScopePolicy, user *UserContext) bool {
	// Empty groups and users = default policy, matches everyone
	if len(policy.Groups) == 0 && len(policy.Users) == 0 {
		return true
	}

	// Check user ID match
	for _, u := range policy.Users {
		if u == user.UserID || u == user.Username || u == user.Email {
			return true
		}
	}

	// Check group match (user's groups or roles)
	for _, pg := range policy.Groups {
		for _, ug := range user.Groups {
			if pg == ug {
				return true
			}
		}
		for _, ur := range user.Roles {
			if pg == ur {
				return true
			}
		}
	}

	return false
}

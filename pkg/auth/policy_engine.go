package auth

import (
	"suse-ai-up/pkg/clients"
	"suse-ai-up/pkg/models"
)

// PolicyEngine evaluates tool access based on authorization policies and user claims.
type PolicyEngine struct {
	policyStore clients.AuthPolicyStore
}

// NewPolicyEngine creates a new policy engine.
func NewPolicyEngine(policyStore clients.AuthPolicyStore) *PolicyEngine {
	return &PolicyEngine{policyStore: policyStore}
}

// UserContext holds the identity claims for policy evaluation.
type UserContext struct {
	UserID         string
	Username       string
	Email          string
	Groups         []string
	Roles          []string
	ResolvedScopes []string // Backend scopes resolved from scope policies for the current adapter
}

// IsToolAllowed evaluates whether a user is authorized to access a specific tool.
// Deny-takes-precedence: if any matching policy denies, access is denied.
// If no policies match the tool, access defaults to allowed (adapter-level fallback).
func (pe *PolicyEngine) IsToolAllowed(adapterName, toolName string, user *UserContext) (bool, string) {
	policies, err := pe.policyStore.ListByAdapterAndTool(adapterName, toolName)
	if err != nil || len(policies) == 0 {
		return true, ""
	}

	return pe.evaluatePolicies(policies, user)
}

// FilterTools filters a list of tool names, returning only those the user is authorized to see.
func (pe *PolicyEngine) FilterTools(adapterName string, toolNames []string, user *UserContext) []string {
	var allowed []string
	for _, toolName := range toolNames {
		if ok, _ := pe.IsToolAllowed(adapterName, toolName, user); ok {
			allowed = append(allowed, toolName)
		}
	}
	return allowed
}

// evaluatePolicies applies deny-takes-precedence logic across sorted policies.
func (pe *PolicyEngine) evaluatePolicies(policies []models.AuthorizationPolicy, user *UserContext) (bool, string) {
	hasMatchingAllow := false

	for _, policy := range policies {
		if !pe.userMatchesPolicy(policy, user) {
			continue
		}

		if policy.Effect == "deny" {
			return false, policy.PolicyID
		}

		if policy.Effect == "allow" {
			hasMatchingAllow = true
		}
	}

	if hasMatchingAllow {
		return true, ""
	}

	// No matching policies — default to allowed (adapter-level fallback)
	return true, ""
}

// userMatchesPolicy checks if the user matches the policy's target criteria.
func (pe *PolicyEngine) userMatchesPolicy(policy models.AuthorizationPolicy, user *UserContext) bool {
	// Check deny lists first
	if policy.Effect == "deny" {
		if containsStr(policy.DeniedUsers, user.UserID) || containsStr(policy.DeniedUsers, user.Username) {
			return true
		}
		if hasOverlap(policy.DeniedGroups, user.Groups) || hasOverlap(policy.DeniedGroups, user.Roles) {
			return true
		}
		// A deny policy with no user/group criteria doesn't match anyone
		if len(policy.DeniedUsers) == 0 && len(policy.DeniedGroups) == 0 {
			return false
		}
		return false
	}

	// Check allow lists
	if policy.Effect == "allow" {
		// Check required scopes first — if specified, user must have ALL of them
		if len(policy.RequiredScopes) > 0 && !hasAllScopes(user.ResolvedScopes, policy.RequiredScopes) {
			return false
		}

		// Wildcard: empty allowed lists means allow all (subject to scope check above)
		if len(policy.AllowedUsers) == 0 && len(policy.AllowedGroups) == 0 {
			return true
		}
		if containsStr(policy.AllowedUsers, user.UserID) || containsStr(policy.AllowedUsers, user.Username) {
			return true
		}
		if hasOverlap(policy.AllowedGroups, user.Groups) || hasOverlap(policy.AllowedGroups, user.Roles) {
			return true
		}
		return false
	}

	return false
}

// hasAllScopes checks that userScopes contains every required scope.
func hasAllScopes(userScopes, requiredScopes []string) bool {
	scopeSet := make(map[string]struct{}, len(userScopes))
	for _, s := range userScopes {
		scopeSet[s] = struct{}{}
	}
	for _, req := range requiredScopes {
		if _, ok := scopeSet[req]; !ok {
			return false
		}
	}
	return true
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func hasOverlap(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}

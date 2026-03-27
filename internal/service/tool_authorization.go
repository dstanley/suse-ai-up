package service

import (
	"fmt"

	"suse-ai-up/pkg/auth"
)

// ToolAuthorizationService handles tool-level access control — filtering tool lists
// and enforcing tool call permissions based on authorization policies.
type ToolAuthorizationService struct {
	policyEngine *auth.PolicyEngine
	auditLogger  *auth.AuditLogger
}

// NewToolAuthorizationService creates a new tool authorization service.
func NewToolAuthorizationService(policyEngine *auth.PolicyEngine, auditLogger *auth.AuditLogger) *ToolAuthorizationService {
	return &ToolAuthorizationService{
		policyEngine: policyEngine,
		auditLogger:  auditLogger,
	}
}

// FilterToolList filters a list of tool names, removing tools the user is not authorized to see.
func (tas *ToolAuthorizationService) FilterToolList(adapterName string, toolNames []string, user *auth.UserContext) []string {
	if tas.policyEngine == nil {
		return toolNames
	}
	return tas.policyEngine.FilterTools(adapterName, toolNames, user)
}

// AuthorizeToolCall checks whether a user is authorized to invoke a specific tool.
// Returns nil if authorized, or an error with the denial reason.
func (tas *ToolAuthorizationService) AuthorizeToolCall(adapterName, toolName string, user *auth.UserContext) error {
	if tas.policyEngine == nil {
		return nil
	}

	allowed, denyPolicyID := tas.policyEngine.IsToolAllowed(adapterName, toolName, user)
	if allowed {
		return nil
	}

	tas.auditLogger.Log(auth.AuditEvent{
		EventType:   auth.AuditEventToolAccessDenied,
		UserID:      user.UserID,
		AdapterName: adapterName,
		ToolName:    toolName,
		Detail:      fmt.Sprintf("denied_by_policy=%s", denyPolicyID),
		Success:     false,
	})

	return fmt.Errorf("insufficient_scope: access to tool '%s' on adapter '%s' is denied by policy %s", toolName, adapterName, denyPolicyID)
}

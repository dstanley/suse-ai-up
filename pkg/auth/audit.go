package auth

import (
	"log"
	"time"
)

// AuditEventType represents the type of authentication/authorization event.
type AuditEventType string

const (
	AuditEventLogin          AuditEventType = "login"
	AuditEventLoginFailed    AuditEventType = "login_failed"
	AuditEventTokenIssued    AuditEventType = "token_issued"
	AuditEventTokenRefreshed AuditEventType = "token_refreshed"
	AuditEventTokenRevoked   AuditEventType = "token_revoked"
	AuditEventTokenExchanged AuditEventType = "token_exchanged"
	AuditEventAccessDenied   AuditEventType = "access_denied"
	AuditEventPolicyChanged  AuditEventType = "policy_changed"
	AuditEventClientRegistered AuditEventType = "client_registered"
	AuditEventToolAccessDenied AuditEventType = "tool_access_denied"
)

// AuditEvent represents a structured audit log entry for compliance review.
type AuditEvent struct {
	Timestamp   time.Time      `json:"timestamp"`
	EventType   AuditEventType `json:"event_type"`
	UserID      string         `json:"user_id,omitempty"`
	ClientID    string         `json:"client_id,omitempty"`
	AdapterName string         `json:"adapter_name,omitempty"`
	ToolName    string         `json:"tool_name,omitempty"`
	SourceIP    string         `json:"source_ip,omitempty"`
	Detail      string         `json:"detail,omitempty"`
	Success     bool           `json:"success"`
}

// AuditLogger provides structured audit logging for auth/authz events.
type AuditLogger struct{}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger() *AuditLogger {
	return &AuditLogger{}
}

// Log writes a structured audit event to the log output.
func (a *AuditLogger) Log(event AuditEvent) {
	event.Timestamp = time.Now()
	status := "SUCCESS"
	if !event.Success {
		status = "FAILURE"
	}

	log.Printf("[AUDIT] %s event=%s user=%s client=%s adapter=%s tool=%s ip=%s detail=%q",
		status,
		event.EventType,
		defaultStr(event.UserID, "-"),
		defaultStr(event.ClientID, "-"),
		defaultStr(event.AdapterName, "-"),
		defaultStr(event.ToolName, "-"),
		defaultStr(event.SourceIP, "-"),
		event.Detail,
	)
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

package security

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// safeIdentifierRe matches only alphanumeric characters, hyphens, underscores, and dots.
var safeIdentifierRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// ValidateIdentifier checks that an identifier (adapter name, user ID, tool name, etc.)
// contains only safe characters and no control characters or CRLF sequences.
func ValidateIdentifier(value, fieldName string) error {
	if value == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	if len(value) > 253 { // Kubernetes name limit
		return fmt.Errorf("%s too long (max 253 chars)", fieldName)
	}
	if !safeIdentifierRe.MatchString(value) {
		return fmt.Errorf("%s contains invalid characters (allowed: a-z, A-Z, 0-9, ., -, _)", fieldName)
	}
	return nil
}

// SanitizeForHeader strips any characters that could enable header injection (CRLF).
// Returns the sanitized value safe for use in HTTP headers.
func SanitizeForHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\x00", "")
	return value
}

// SanitizeForLog strips newlines and control characters that could enable log injection.
func SanitizeForLog(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\x00", "")
	return value
}

// ValidateRemoteURL checks that a URL is safe for server-side requests (anti-SSRF).
// It rejects localhost, private IP ranges, link-local, and cloud metadata endpoints.
func ValidateRemoteURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("URL cannot be empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https, got %q", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL must have a hostname")
	}

	// Block obvious localhost variants
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || lowerHost == "127.0.0.1" || lowerHost == "::1" || lowerHost == "[::1]" {
		return fmt.Errorf("localhost URLs are not allowed for remote adapters")
	}

	// Resolve the hostname and check the IP
	ip := net.ParseIP(host)
	if ip != nil {
		if err := validateIP(ip); err != nil {
			return err
		}
	}

	return nil
}

// validateIP checks that an IP address is not in a reserved or private range.
func validateIP(ip net.IP) error {
	if ip.IsLoopback() {
		return fmt.Errorf("loopback addresses are not allowed")
	}
	if ip.IsPrivate() {
		return fmt.Errorf("private IP addresses are not allowed for remote adapters")
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("link-local addresses are not allowed")
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("unspecified addresses are not allowed")
	}
	// Block cloud metadata endpoint (169.254.169.254)
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return fmt.Errorf("cloud metadata endpoint is not allowed")
	}
	return nil
}

// ValidateShellArg checks that a value is safe for interpolation into a shell command.
// It rejects shell metacharacters, backticks, $(), and other injection vectors.
var unsafeShellChars = regexp.MustCompile("[`$;|&><(){}\\[\\]!#~\\\\'\"]")

func ValidateShellArg(value, fieldName string) error {
	if value == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	if unsafeShellChars.MatchString(value) {
		return fmt.Errorf("%s contains unsafe shell characters", fieldName)
	}
	if strings.Contains(value, "\n") || strings.Contains(value, "\r") {
		return fmt.Errorf("%s contains newlines", fieldName)
	}
	return nil
}

// ValidateGitURL checks that a URL looks like a valid git repository URL
// and does not contain shell injection characters.
func ValidateGitURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("git URL cannot be empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid git URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("git URL scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("git URL must have a hostname")
	}
	// Check the path doesn't contain shell metacharacters
	if unsafeShellChars.MatchString(u.Path) {
		return fmt.Errorf("git URL path contains unsafe characters")
	}
	return nil
}

// SafeRepoName extracts and validates a repository name from a git URL.
// Returns the sanitized repo name or an error.
func SafeRepoName(gitURL string) (string, error) {
	parts := strings.Split(gitURL, "/")
	repoName := parts[len(parts)-1]
	if strings.HasSuffix(repoName, ".git") {
		repoName = repoName[:len(repoName)-4]
	}
	if err := ValidateIdentifier(repoName, "repository name"); err != nil {
		return "", err
	}
	return repoName, nil
}

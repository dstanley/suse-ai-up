package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SPIFFEClient wraps the SPIRE Workload API for fetching SVIDs.
// It manages a long-lived connection to the SPIRE agent and provides
// JWT SVIDs (for RFC 8693 token exchange) and X.509 SVIDs (for mTLS).
type SPIFFEClient struct {
	socketPath string
	client     *workloadapi.Client
	x509Source *workloadapi.X509Source
	mu         sync.RWMutex
	cancel     context.CancelFunc
}

// NewSPIFFEClient creates a new SPIFFE client connected to the SPIRE agent.
func NewSPIFFEClient(socketPath string) (*SPIFFEClient, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Use a timeout for the initial connection to prevent blocking startup
	// indefinitely if the SPIRE agent socket is not available
	connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connectCancel()

	client, err := workloadapi.New(connectCtx, workloadapi.WithAddr("unix://"+socketPath))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to SPIRE agent at %s: %w", socketPath, err)
	}

	x509Ctx, x509Cancel := context.WithTimeout(ctx, 10*time.Second)
	defer x509Cancel()

	x509Source, err := workloadapi.NewX509Source(x509Ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+socketPath)))
	if err != nil {
		client.Close()
		cancel()
		return nil, fmt.Errorf("failed to create X.509 source: %w", err)
	}

	sc := &SPIFFEClient{
		socketPath: socketPath,
		client:     client,
		x509Source: x509Source,
		cancel:     cancel,
	}

	log.Printf("[SPIFFE] Connected to SPIRE agent at %s", socketPath)
	return sc, nil
}

// FetchJWTSVID fetches a JWT SVID from the SPIRE agent for the given audience.
// The returned JWT can be used as a subject_token in RFC 8693 token exchange.
func (sc *SPIFFEClient) FetchJWTSVID(ctx context.Context, audience string) (string, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	if sc.client == nil {
		return "", fmt.Errorf("SPIFFE client not initialized")
	}

	params := jwtsvid.Params{
		Audience: audience,
	}

	svids, err := sc.client.FetchJWTSVIDs(ctx, params)
	if err != nil {
		return "", fmt.Errorf("failed to fetch JWT SVID: %w", err)
	}

	if len(svids) == 0 {
		return "", fmt.Errorf("no JWT SVIDs returned by SPIRE agent")
	}

	return svids[0].Marshal(), nil
}

// GetTLSConfig returns a TLS configuration using X.509 SVIDs for mTLS.
// The returned config auto-rotates certificates as the SPIRE agent renews them.
func (sc *SPIFFEClient) GetTLSConfig(authorizedID string) (*tls.Config, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	if sc.x509Source == nil {
		return nil, fmt.Errorf("X.509 source not initialized")
	}

	if authorizedID != "" {
		// Restrict connections to a specific SPIFFE ID
		targetID, err := spiffeid.FromString(authorizedID)
		if err != nil {
			return nil, fmt.Errorf("invalid SPIFFE ID %q: %w", authorizedID, err)
		}
		return tlsconfig.MTLSClientConfig(sc.x509Source, sc.x509Source, tlsconfig.AuthorizeID(targetID)), nil
	}

	// Accept any SPIFFE ID in the trust domain
	return tlsconfig.MTLSClientConfig(sc.x509Source, sc.x509Source, tlsconfig.AuthorizeAny()), nil
}

// GetSVIDInfo returns the current X.509 SVID's SPIFFE ID and certificate details.
func (sc *SPIFFEClient) GetSVIDInfo() (spiffeID string, notAfter time.Time, err error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	if sc.x509Source == nil {
		return "", time.Time{}, fmt.Errorf("X.509 source not initialized")
	}

	svid, err := sc.x509Source.GetX509SVID()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get X.509 SVID: %w", err)
	}

	var certs []*x509.Certificate
	certs = svid.Certificates
	if len(certs) == 0 {
		return "", time.Time{}, fmt.Errorf("no certificates in X.509 SVID")
	}

	return svid.ID.String(), certs[0].NotAfter, nil
}

// Close shuts down the SPIFFE client and releases resources.
func (sc *SPIFFEClient) Close() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.x509Source != nil {
		if err := sc.x509Source.Close(); err != nil {
			log.Printf("[SPIFFE] Warning: error closing X.509 source: %v", err)
		}
	}
	if sc.client != nil {
		if err := sc.client.Close(); err != nil {
			log.Printf("[SPIFFE] Warning: error closing workload API client: %v", err)
		}
	}
	if sc.cancel != nil {
		sc.cancel()
	}

	log.Printf("[SPIFFE] Client closed")
	return nil
}

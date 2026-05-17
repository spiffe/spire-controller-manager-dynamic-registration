package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Config struct {
	SpireServerUDSPath  string
	TrustDomain         string
	ServerSpiffeID      string
	AllowedIDPrefix     string
	ExpectedServiceAcct string
	EntryPrefix         string
	ExpectedAudience    string
	RegistrationPrefix  string
}

type SecurityManager struct {
	mu           sync.RWMutex
	tlsCert      *tls.Certificate
	x509Roots    *x509.CertPool
	svidClient   svidv1.SVIDClient
	bundleClient bundlev1.BundleClient
	config       *Config
	privateKey   *ecdsa.PrivateKey
}

func NewSecurityManager(cfg *Config, svidClient svidv1.SVIDClient, bundleClient bundlev1.BundleClient) (*SecurityManager, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate runtime private key: %w", err)
	}

	return &SecurityManager{
		svidClient:   svidClient,
		bundleClient: bundleClient,
		config:       cfg,
		privateKey:   privKey,
	}, nil
}

func (sm *SecurityManager) MintAndRotate(ctx context.Context) error {
	spiffeURI, err := url.Parse(sm.config.ServerSpiffeID)
	if err != nil {
		return fmt.Errorf("invalid target spiffe id format: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: spiffeURI.String()},
		URIs:     []*url.URL{spiffeURI},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, sm.privateKey)
	if err != nil {
		return fmt.Errorf("failed to generate certificate signing request: %w", err)
	}

	req := &svidv1.MintX509SVIDRequest{
		Csr: csrDER,
		Ttl: 3600,
	}

	resp, err := sm.svidClient.MintX509SVID(ctx, req)
	if err != nil {
		return fmt.Errorf("spire minting error: %w", err)
	}

	if resp.Svid == nil || len(resp.Svid.CertChain) == 0 {
		return errors.New("spire returned an empty cert chain")
	}

	leafCert, err := x509.ParseCertificate(resp.Svid.CertChain[0])
	if err != nil {
		return fmt.Errorf("failed to parse leaf cert: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{leafCert.Raw},
		PrivateKey:  sm.privateKey,
	}

	sm.mu.Lock()
	sm.tlsCert = tlsCert
	sm.mu.Unlock()

	log.Println("Successfully rotated local server X509-SVID.")
	return nil
}

func (sm *SecurityManager) FetchAndApplyTrustBundle(ctx context.Context) error {
	bundle, err := sm.bundleClient.GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return fmt.Errorf("failed fetching spire trust bundle: %w", err)
	}

	if bundle == nil {
		return errors.New("received nil bundle response from spire server")
	}

	rootPool := x509.NewCertPool()
	for _, rootCertRaw := range bundle.X509Authorities {
		if bCert, err := x509.ParseCertificate(rootCertRaw.Asn1); err == nil {
			rootPool.AddCert(bCert)
		}
	}

	sm.mu.Lock()
	sm.x509Roots = rootPool
	sm.mu.Unlock()

	log.Printf("Trust bundle updated. Total roots tracked: %d", len(bundle.X509Authorities))
	return nil
}

func (sm *SecurityManager) StartRotationLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := sm.MintAndRotate(ctx); err != nil {
					log.Printf("Error updating SPIRE credentials: %v", err)
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

func (sm *SecurityManager) StartTrustBundleWatcher(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := sm.FetchAndApplyTrustBundle(ctx); err != nil {
					log.Printf("Error updating SPIRE trust bundle: %v", err)
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

func (sm *SecurityManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.tlsCert == nil {
		return nil, errors.New("no certificate available yet")
	}
	return sm.tlsCert, nil
}

func (sm *SecurityManager) VerifyPeer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if len(rawCerts) == 0 {
		return errors.New("client certificate required")
	}

	clientCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %w", err)
	}

	if sm.x509Roots == nil {
		return errors.New("mTLS root validation pool is not initialized yet")
	}

	opts := x509.VerifyOptions{
		Roots:       sm.x509Roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: time.Now(),
	}
	if _, err := clientCert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify client certificate chain: %w", err)
	}

	for _, u := range clientCert.URIs {
		if u.Scheme == "spiffe" {
			spiffeID := u.String()
			if strings.HasPrefix(spiffeID, sm.config.AllowedIDPrefix) {
				return nil
			}
		}
	}

	return errors.New("unauthorized client SPIFFE ID")
}

type ServerContext struct {
	Config      *Config
	K8sClient   *kubernetes.Clientset
	EntryClient entryv1.EntryClient
}

func main() {
	cfg := &Config{
		TrustDomain:         os.Getenv("SPIFFE_TRUST_DOMAIN"),
		SpireServerUDSPath:  os.Getenv("SPIRE_SERVER_SOCKET_PATH"),
		ServerSpiffeID:      os.Getenv("SERVER_SPIFFE_ID"),
		AllowedIDPrefix:     os.Getenv("ALLOWEDID_PREFIX"),
		ExpectedServiceAcct: os.Getenv("EXPECTED_SERVICE_ACCOUNT"),
		EntryPrefix:         os.Getenv("ENTRY_PREFIX"),
		ExpectedAudience:    os.Getenv("EXPECTED_AUDIENCE"),
		RegistrationPrefix:  os.Getenv("REGISTRATION_PREFIX"),
	}

	if cfg.TrustDomain == "" {
		log.Fatalf("You must specify a trust domain using SPIFFE_TRUST_DOMAIN")
	}
	if cfg.ExpectedServiceAcct == "" {
		cfg.ExpectedServiceAcct = "spire-system:spire-agent"
	}
	cfg.ExpectedServiceAcct = "system:serviceaccount:" + cfg.ExpectedServiceAcct

	if cfg.EntryPrefix == "" {
		cfg.EntryPrefix = "scmnr"
	}

	if cfg.RegistrationPrefix == "" {
		cfg.RegistrationPrefix = "k8s/agent"
	}
	if !strings.HasPrefix(cfg.RegistrationPrefix, "/") {
		cfg.RegistrationPrefix  = "/" + cfg.RegistrationPrefix
	}
	if !strings.HasSuffix(cfg.RegistrationPrefix, "/") {
		cfg.RegistrationPrefix += "/"
	}

	if cfg.ExpectedAudience == "" {
		cfg.ExpectedAudience = "spire-controller-manager-node-registrar"
	}

	if cfg.SpireServerUDSPath == "" {
		cfg.SpireServerUDSPath = "/tmp/spire-server/private/api.sock"
	}

	if cfg.ServerSpiffeID == "" {
		cfg.ServerSpiffeID = "spire-controller-manager-dynamic-registration"
	}
	if !strings.HasPrefix(cfg.ServerSpiffeID, "/") {
		cfg.ServerSpiffeID  = "/" + cfg.ServerSpiffeID
	}
	if !strings.HasPrefix(cfg.ServerSpiffeID, "spiffe://") {
		url, err := url.Parse(fmt.Sprintf("spiffe://%s%s", cfg.TrustDomain, cfg.ServerSpiffeID))
		if err != nil {
			log.Fatalf("Invalid target spiffe id format: %v", err)
		}
		cfg.ServerSpiffeID = url.String()
	}

	if cfg.AllowedIDPrefix == "" {
		cfg.AllowedIDPrefix = "spire/agent/x509pop"
	}
	if !strings.HasSuffix(cfg.AllowedIDPrefix, "/") {
		cfg.AllowedIDPrefix += "/"
	}
	if !strings.HasPrefix(cfg.AllowedIDPrefix, "/") {
		cfg.AllowedIDPrefix = "/" + cfg.AllowedIDPrefix
	}
	if !strings.HasPrefix(cfg.AllowedIDPrefix, "spiffe://") {
		url, err := url.Parse(fmt.Sprintf("spiffe://%s%s", cfg.TrustDomain, cfg.AllowedIDPrefix))
		if err != nil {
			log.Fatalf("Invalid target spiffe id format: %v", err)
		}
		cfg.AllowedIDPrefix = url.String()
	}

	if cfg.EntryPrefix != "" && !strings.HasSuffix(cfg.EntryPrefix, ".") {
		cfg.EntryPrefix += "."
	}

	target := fmt.Sprintf("unix://%s", cfg.SpireServerUDSPath)
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to SPIRE Private API UDS: %v", err)
	}
	defer conn.Close()

	svidClient := svidv1.NewSVIDClient(conn)
	entryClient := entryv1.NewEntryClient(conn)
	bundleClient := bundlev1.NewBundleClient(conn)

	secMgr, err := NewSecurityManager(cfg, svidClient, bundleClient)
	if err != nil {
		log.Fatalf("Failed to initialize security engine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := secMgr.MintAndRotate(ctx); err != nil {
		log.Fatalf("Initial identity provisioning failed: %v", err)
	}
	if err := secMgr.FetchAndApplyTrustBundle(ctx); err != nil {
		log.Fatalf("Initial trust bundle population failed: %v", err)
	}

	secMgr.StartRotationLoop(ctx, 15 * time.Minute)
	secMgr.StartTrustBundleWatcher(ctx, 15 * time.Minute)

	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to initialize in-cluster K8s configuration: %v", err)
	}
	k8sClient, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		log.Fatalf("Failed to instantiate K8s clientset: %v", err)
	}

	srvCtx := &ServerContext{
		Config:      cfg,
		K8sClient:   k8sClient,
		EntryClient: entryClient,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/register-node", srvCtx.RegisterNodeHandler)

	tlsConfig := &tls.Config{
		GetCertificate:        secMgr.GetCertificate,
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: secMgr.VerifyPeer,
	}

	server := &http.Server{
		Addr:      ":8931",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting registration control plane server on :8931 connected to UDS: %s\n", cfg.SpireServerUDSPath)
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server HTTP execution error: %v", err)
	}
}

func (sc *ServerContext) RegisterNodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "mTLS verification required", http.StatusUnauthorized)
		return
	}
	var clientSpiffeID string
	for _, u := range r.TLS.PeerCertificates[0].URIs {
		if u.Scheme == "spiffe" {
			clientSpiffeID = u.String()
			break
		}
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or malformed Authorization header", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	nodeUID, err := extractNodeUIDFromJWT(token, sc.Config.ExpectedAudience)
	if err != nil {
		log.Printf("Token structure error: %v", err)
		http.Error(w, "Invalid token layout", http.StatusBadRequest)
		return
	}

	tokenReview, err := sc.K8sClient.AuthenticationV1().TokenReviews().Create(r.Context(), &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{sc.Config.ExpectedAudience},
		},
	}, metav1.CreateOptions{})

	if err != nil {
		log.Printf("K8s TokenReview execution failure: %v", err)
		http.Error(w, "Internal validation fault", http.StatusInternalServerError)
		return
	}

	if !tokenReview.Status.Authenticated {
		http.Error(w, "Token failed validation against API server", http.StatusUnauthorized)
		return
	}

	if tokenReview.Status.User.Username != sc.Config.ExpectedServiceAcct {
		log.Printf("Identity rejected: Expected %s, got %s", sc.Config.ExpectedServiceAcct, tokenReview.Status.User.Username)
		http.Error(w, "Forbidden Subject Identity", http.StatusForbidden)
		return
	}

	targetSpiffeID := fmt.Sprintf("spiffe://%s/k8s/agent/%s", sc.Config.TrustDomain, nodeUID)

	entryReq := &entryv1.BatchCreateEntryRequest{
		Entries: []*types.Entry{
			{
				Id: sc.Config.EntryPrefix + nodeUID,
				SpiffeId: &types.SPIFFEID{TrustDomain: sc.Config.TrustDomain, Path: sc.Config.RegistrationPrefix + nodeUID},
				ParentId: &types.SPIFFEID{TrustDomain: sc.Config.TrustDomain, Path: "/spire/server"},
				Selectors: []*types.Selector{
					{Type: "spiffe_id", Value: clientSpiffeID},
				},
			},
		},
	}

	resp, err := sc.EntryClient.BatchCreateEntry(r.Context(), entryReq)
	if err != nil {
		log.Printf("SPIRE registration failure: %v", err)
		http.Error(w, "Failed to provision target entry", http.StatusInternalServerError)
		return
	}

	for _, res := range resp.Results {
		if res.Status.Code != 0 {
			log.Printf("SPIRE entry creation returned error status code: %d message: %s", res.Status.Code, res.Status.Message)
			http.Error(w, "SPIRE storage engine error", http.StatusInternalServerError)
			return
		}
		log.Printf("Successfully saved SPIRE entry ID: %s for target targetSpiffeID: %s", res.Entry.Id, targetSpiffeID)
	}

	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"status":"success"}`))
}

func extractNodeUIDFromJWT(tokenStr string, expectedAud string) (string, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) < 2 {
		return "", errors.New("malformed token payload structure")
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed decoding token claims segment: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return "", fmt.Errorf("failed parsing claims json: %w", err)
	}

	audClaim, ok := claims["aud"]
	if !ok {
		return "", errors.New("missing audience claim in token")
	}

	audMatched := false
	switch v := audClaim.(type) {
	case string:
		if v == expectedAud {
			audMatched = true
		}
	case []interface{}:
		for _, a := range v {
			if strAud, ok := a.(string); ok && strAud == expectedAud {
				audMatched = true
				break
			}
		}
	}

	if !audMatched {
		return "", fmt.Errorf("token audience mismatch: expected %s", expectedAud)
	}

	if k8sClaims, ok := claims["kubernetes.io"].(map[string]interface{}); ok {
		if nodeClaims, ok := k8sClaims["node"].(map[string]interface{}); ok {
			if uid, ok := nodeClaims["uid"].(string); ok && uid != "" {
				return uid, nil
			}
		}
	}

	return "", errors.New("node.uid claim field absent in token payload")
}

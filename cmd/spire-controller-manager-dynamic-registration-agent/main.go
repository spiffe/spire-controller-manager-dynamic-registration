package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type KeysConfig struct {
	Keys map[string]string `json:"keys"`
}

type AgentData struct {
	SVID   []string `json:"svid"`
	Bundle []string `json:"bundle"`
}

func main() {
	trustDomain := os.Getenv("SPIFFE_TRUST_DOMAIN")
	keyFile := os.Getenv("KEYFILE")
	dataFile := os.Getenv("DATAFILE")
	serverSpiffeID := os.Getenv("SERVERSPIFFEID")
	apiURL := os.Getenv("APIURL")
	apiPort := os.Getenv("APIPORT")
	tokenFile := os.Getenv("TOKENFILE")

	if trustDomain == "" {
		log.Printf("You must specify the trust domain")
		os.Exit(1)
	}
	if apiURL == ""  {
		log.Printf("You must specify the server api url")
		os.Exit(1)
	}
	if tokenFile == "" {
		log.Printf("You must specify the token file")
		os.Exit(1)
	}

	if serverSpiffeID == "" {
		serverSpiffeID = "spire-controller-manager-dynamic-registration"
	}
	if !strings.HasPrefix(serverSpiffeID, "/") && !strings.HasPrefix(serverSpiffeID, "spiffe://") {
		serverSpiffeID = "/" + serverSpiffeID
	}
	if !strings.HasPrefix(serverSpiffeID, "spiffe://") {
		serverSpiffeID = "spiffe://" + serverSpiffeID
	}

	if !strings.HasPrefix(apiURL, "https://") {
		apiURL = "https://" + apiURL
	}
	if !strings.Contains(apiURL, ".") {
		apiURL += "." + trustDomain
	}
	if apiPort != "" && !strings.Contains(apiURL,":") {
		apiURL += ":" + apiPort
	}
	if !strings.HasSuffix(apiURL, "/") {
		apiURL += "/"
	}
	apiURL += "v1/register-node"

	if keyFile == "" {
		keyFile = "/var/lib/spire/keys.json"
	}

	if dataFile == "" {
		dataFile = "/var/lib/spire/agent-data.json"
	}

	for {
		log.Println("--- Attempting to refresh credentials ---")

		clientCert, bundlePool, err := loadCredentials(keyFile, dataFile)
		if err != nil {
			log.Printf("Credential Error: %v. Retrying in 10s...", err)
			time.Sleep(10 * time.Second)
			continue
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      bundlePool,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return fmt.Errorf("no server certificates provided")
				}
				leaf := cs.PeerCertificates[0]
				for _, uri := range leaf.URIs {
					if uri.String() == serverSpiffeID {
						return nil
					}
				}
				return fmt.Errorf("server SPIFFE ID mismatch: found %v, expected %s", leaf.URIs, serverSpiffeID)
			},
		}

		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
			Timeout:   15 * time.Second,
		}

		log.Printf("Making request to %s...", apiURL)
		//FIXME load token from disk.
		token, err := loadProjectedToken(tokenFile)
		if err != nil {
			log.Printf("Failed to read token")
		} else {
			err = performRequest(client, apiURL, token)
			if err == nil {
				log.Printf("Successfully uploaded. Sleeping forever")
				select {}
			}
		}

		time.Sleep(10 * time.Second)
	}
}

func loadProjectedToken(tokenFile string) (string, error) {
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read projected token file %q: %w", tokenFile, err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("projected token file %q was empty", tokenFile)
	}

	return token, nil
}

func loadCredentials(keyPath string, dataPath string) (tls.Certificate, *x509.CertPool, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to read %s: %w", keyPath, err)
	}
	var keysConfig KeysConfig
	if err := json.Unmarshal(keyData, &keysConfig); err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to unmarshal keys: %w", err)
	}

	agentRaw, err := os.ReadFile(dataPath)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to read %s: %w", dataPath, err)
	}
	var agentData AgentData
	if err := json.Unmarshal(agentRaw, &agentData); err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to unmarshal agent data: %w", err)
	}

	bundlePool := x509.NewCertPool()
	for _, b64Cert := range agentData.Bundle {
		der, _ := base64.StdEncoding.DecodeString(b64Cert)
		if !bundlePool.AppendCertsFromPEM(der) {
			if c, err := x509.ParseCertificate(der); err == nil {
				bundlePool.AddCert(c)
			}
		}
	}

	privKeyMap := make(map[string]crypto.PrivateKey)
	for label, b64Key := range keysConfig.Keys {
		der, err := base64.StdEncoding.DecodeString(b64Key)
		if err != nil {
			continue
		}
		priv, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			log.Printf("Warning: key %s is not valid PKCS8: %v", label, err)
			continue
		}

		if ecdsaPriv, ok := priv.(*ecdsa.PrivateKey); ok {
			pubBytes, _ := x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
			privKeyMap[string(pubBytes)] = priv
		}
	}

	var bestCert *x509.Certificate
	var bestPriv crypto.PrivateKey
	now := time.Now()

	for _, b64Cert := range agentData.SVID {
		raw, err := base64.StdEncoding.DecodeString(b64Cert)
		if err != nil {
			continue
		}

		cert, err := parseX509(raw)
		if err != nil {
			log.Printf("Warning: failed to parse SVID entry: %v", err)
			continue
		}

		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			log.Printf("Skipping cert %s: Expired (Valid until %v)", cert.Subject, cert.NotAfter)
			continue
		}

		pubBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if priv, ok := privKeyMap[string(pubBytes)]; ok {
			if bestCert == nil || cert.NotBefore.After(bestCert.NotBefore) {
				bestCert = cert
				bestPriv = priv
			}
		} else {
			log.Printf("Skipping cert %s: No matching private key found in keys.json", cert.Subject)
		}
	}

	if bestCert == nil {
		return tls.Certificate{}, nil, fmt.Errorf("no valid SVID found (all were expired or missing keys)")
	}

	log.Printf("Using SVID: %s (Expires: %v)", bestCert.Subject, bestCert.NotAfter)

	return tls.Certificate{
		Certificate: [][]byte{bestCert.Raw},
		PrivateKey:  bestPriv,
		Leaf:        bestCert,
	}, bundlePool, nil
}

func parseX509(data []byte) (*x509.Certificate, error) {
	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert, nil
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("data is neither valid DER nor PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func performRequest(client *http.Client, url string, token string) error {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte("{}")))
	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("HTTP Request failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("Response: %s (Length: %d)", resp.Status, len(body))
	if resp.StatusCode != 200 {
		return fmt.Errorf("request failed: %s | server message: %s", resp.Status, string(body))
	}
	return nil
}

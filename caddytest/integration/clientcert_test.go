package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// clientCertChain is a generated certificate chain for test clients.
type clientCertChain struct {
	cert tls.Certificate
}

// newTestCA creates a self-signed CA certificate and its private key.
func newTestCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	return cert, key
}

// newTestClientCert issues a client certificate signed by parent, returning a
// tls.Certificate whose chain includes the leaf and any intermediates up to
// (but excluding) the root.
func newTestClientCert(t *testing.T, cn string, org, ou []string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, intermediates ...*x509.Certificate) clientCertChain {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       org,
			OrganizationalUnit: ou,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("creating client certificate: %v", err)
	}
	chain := clientCertChain{cert: tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  key,
	}}
	for _, intermediate := range intermediates {
		chain.cert.Certificate = append(chain.cert.Certificate, intermediate.Raw)
	}
	return chain
}

// newIntermediateCA issues an intermediate CA certificate signed by parent.
func newIntermediateCA(t *testing.T, commonName string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating intermediate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("creating intermediate certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing intermediate certificate: %v", err)
	}
	return cert, key
}

// httpClientWithCert returns an HTTP client that presents the given client
// certificate chain, dialing localhost like the other integration tests.
func httpClientWithCert(chains ...clientCertChain) *http.Client {
	transport := caddytest.CreateTestingTransport()
	for _, chain := range chains {
		transport.TLSClientConfig.Certificates = append(transport.TLSClientConfig.Certificates, chain.cert)
	}
	if len(chains) > 0 {
		// always present the certificate, even if its issuer is not in the
		// server's acceptable-CA list, so that untrusted chains actually
		// reach the server's verification logic
		transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &chains[0].cert, nil
		}
	}
	return &http.Client{Transport: transport}
}

// writeTestServerCert issues a server certificate for localhost signed by
// parent and writes the certificate and key PEM files into dir.
func writeTestServerCert(t *testing.T, dir string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating server key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("creating server certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling server key: %v", err)
	}
	certFile = filepath.Join(dir, "server.pem")
	keyFile = filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing server certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("writing server key: %v", err)
	}
	return certFile, keyFile
}

// TestClientCertRouting verifies mTLS edge routing: the gateway verifies
// client certificates against a trust pool (verify_if_given), routes verified
// requests by certificate fields, and falls back for clients without a
// verified certificate. It exercises three certificate chain shapes:
// leaf-signed-by-root, leaf-via-intermediate, and leaf-from-untrusted-CA.
func TestClientCertRouting(t *testing.T) {
	// trusted PKI: root -> intermediate -> leaf
	rootCA, rootKey := newTestCA(t, "Test Root CA")
	intermediateCA, intermediateKey := newIntermediateCA(t, "Test Intermediate CA", rootCA, rootKey)

	// untrusted PKI: a different root the gateway does not trust
	untrustedCA, untrustedKey := newTestCA(t, "Untrusted Root CA")

	// chain 1: leaf signed directly by the trusted root
	directClient := newTestClientCert(t, "direct-client", []string{"Edge-Gateway"}, nil, rootCA, rootKey)
	// chain 2: leaf signed by the intermediate, chaining to the trusted root
	viaIntermediateClient := newTestClientCert(t, "intermediate-client", []string{"Edge-Gateway"}, []string{"team-blue"}, intermediateCA, intermediateKey, intermediateCA)
	// chain 3: leaf signed by an untrusted CA (same subject fields, to prove
	// that verification -- not mere field presence -- gates routing)
	untrustedClient := newTestClientCert(t, "untrusted-client", []string{"Edge-Gateway"}, nil, untrustedCA, untrustedKey)

	tmpDir := t.TempDir()
	rootCAPEM := filepath.Join(tmpDir, "root-ca.pem")
	err := os.WriteFile(rootCAPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCA.Raw}), 0o600)
	if err != nil {
		t.Fatalf("writing root CA PEM: %v", err)
	}
	serverCert, serverKey := writeTestServerCert(t, tmpDir, rootCA, rootKey)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
	}

	localhost {
		tls %s %s {
			client_auth {
				mode verify_if_given
				trust_pool file %s
			}
		}

		@blue client_cert {
			verified
			subject_organizational_unit team-blue
		}
		@gateway client_cert {
			verified
			subject_organization Edge-Gateway
		}

		route {
			handle @blue {
				respond "team-blue backend" 200
			}
			handle @gateway {
				respond "edge gateway backend" 200
			}
			handle {
				respond "fallback: no verified client certificate" 403
			}
		}
	}`, serverCert, serverKey, rootCAPEM), "caddyfile")

	t.Run("leaf signed by root is routed by organization", func(t *testing.T) {
		assertClientCertResponse(t, httpClientWithCert(directClient), 200, "edge gateway backend")
	})

	t.Run("leaf via intermediate chain is routed by organizational unit", func(t *testing.T) {
		assertClientCertResponse(t, httpClientWithCert(viaIntermediateClient), 200, "team-blue backend")
	})

	t.Run("leaf from untrusted CA is rejected at the handshake", func(t *testing.T) {
		resp, err := httpClientWithCert(untrustedClient).Get("https://localhost:9443")
		if err == nil {
			resp.Body.Close()
			t.Fatalf("expected TLS handshake failure for untrusted client certificate, got status %d", resp.StatusCode)
		}
	})

	t.Run("no client certificate falls back", func(t *testing.T) {
		assertClientCertResponse(t, httpClientWithCert(), 403, "fallback: no verified client certificate")
	})
}

func assertClientCertResponse(t *testing.T, client *http.Client, expectedStatus int, expectedBody string) {
	t.Helper()
	resp, err := client.Get("https://localhost:9443")
	if err != nil {
		t.Fatalf("performing request: %v", err)
	}
	defer resp.Body.Close()
	body := make([]byte, len(expectedBody)+1)
	n, _ := resp.Body.Read(body)
	body = body[:n]
	if resp.StatusCode != expectedStatus {
		t.Fatalf("expected status %d, got %d (body: %s)", expectedStatus, resp.StatusCode, body)
	}
	if string(body) != expectedBody {
		t.Fatalf("expected body %q, got %q", expectedBody, body)
	}
}

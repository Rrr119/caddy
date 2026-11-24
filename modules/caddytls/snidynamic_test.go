// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The three SNI host names used by the acceptance test.
var testThreeSNIs = []string{"sni-one.test", "sni-two.test", "sni-three.test"}

// sniPKI is a tiny certificate authority that issues server certificates.
type sniPKI struct {
	t      *testing.T
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	pool   *x509.CertPool
	serial int64
	mu     sync.Mutex
}

func newSNIPKI(t *testing.T) *sniPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SNI Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("appending CA to pool failed")
	}
	return &sniPKI{t: t, caCert: caCert, caKey: caKey, pool: pool, serial: 1}
}

// issuedCert is a certificate for one SNI name in both PEM and parsed forms.
type issuedCert struct {
	name            string
	serial          *big.Int
	certPEM, keyPEM []byte
	tlsCert         tls.Certificate
}

func (p *sniPKI) issue(name string) *issuedCert {
	p.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatalf("generating leaf key for %s: %v", name, err)
	}
	p.mu.Lock()
	p.serial++
	serial := big.NewInt(p.serial)
	p.mu.Unlock()

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		p.t.Fatalf("creating leaf for %s: %v", name, err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		p.t.Fatalf("marshaling key for %s: %v", name, err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		p.t.Fatalf("loading key pair for %s: %v", name, err)
	}
	tlsCert.Leaf, err = x509.ParseCertificate(der)
	if err != nil {
		p.t.Fatalf("parsing leaf for %s: %v", name, err)
	}
	return &issuedCert{
		name:    name,
		serial:  serial,
		certPEM: certPEM,
		keyPEM:  keyPEM,
		tlsCert: tlsCert,
	}
}

func (c *issuedCert) writePair(t *testing.T, dir, base string) (certFile, keyFile string) {
	t.Helper()
	certFile = filepath.Join(dir, base+".crt")
	keyFile = filepath.Join(dir, base+".key")
	if err := os.WriteFile(certFile, c.certPEM, 0o600); err != nil {
		t.Fatalf("writing cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, c.keyPEM, 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return certFile, keyFile
}

// startSNITLSServer serves cfg on an ephemeral loopback port.
func startSNITLSServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSNITestConn(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-acceptDone
	})
	return ln.Addr().String()
}

func serveSNITestConn(raw net.Conn) {
	defer raw.Close()
	conn, ok := raw.(*tls.Conn)
	if !ok {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := conn.Handshake(); err != nil {
		return
	}
	_, _ = conn.Write([]byte("ok\n"))
}

// dialSNI performs one TLS handshake and drains the connection until EOF so
// that TLS 1.3 post-handshake session tickets are written into cache.
func dialSNI(t *testing.T, addr, sni string, pool *x509.CertPool, cache tls.ClientSessionCache) tls.ConnectionState {
	t.Helper()
	dialer := net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dialing %s for SNI %s: %v", addr, sni, err)
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		RootCAs:            pool,
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: cache,
	})
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := conn.Handshake(); err != nil {
		t.Fatalf("TLS handshake for SNI %s: %v", sni, err)
	}
	// The server closes after writing; draining processes any NewSessionTicket
	// messages before the second handshake attempts resumption.
	_, _ = io.Copy(io.Discard, conn)
	return conn.ConnectionState()
}

func assertPresentedCert(t *testing.T, state tls.ConnectionState, want *issuedCert) {
	t.Helper()
	if len(state.PeerCertificates) == 0 {
		t.Fatalf("SNI %s: no peer certificates", want.name)
	}
	got := state.PeerCertificates[0]
	if got.SerialNumber.Cmp(want.serial) != 0 {
		t.Fatalf("SNI %s: expected serial %s, got %s (DNS %v)",
			want.name, want.serial, got.SerialNumber, got.DNSNames)
	}
	if len(got.DNSNames) == 0 || got.DNSNames[0] != want.name {
		t.Fatalf("SNI %s: unexpected DNS names %v", want.name, got.DNSNames)
	}
}

// TestSNIDynamic_ThreeSNIsCertificatesAndResumption is the acceptance test:
// three SNI hosts are loaded dynamically from cert/key files, each handshake
// presents the correct certificate, and a second connection with a shared
// session cache resumes the TLS session for every SNI.
func TestSNIDynamic_ThreeSNIsCertificatesAndResumption(t *testing.T) {
	pki := newSNIPKI(t)
	dir := t.TempDir()

	store := NewSNICertificateStore()
	issued := make(map[string]*issuedCert, len(testThreeSNIs))
	for _, sni := range testThreeSNIs {
		cert := pki.issue(sni)
		issued[sni] = cert
		certFile, keyFile := cert.writePair(t, dir, sni)
		store.AddCertificateFile(sni, certFile, keyFile)
	}

	rotator, err := NewSessionTicketRotator(4)
	if err != nil {
		t.Fatalf("creating ticket rotator: %v", err)
	}
	cfg := store.TLSConfig(nil, rotator)
	addr := startSNITLSServer(t, cfg)

	// One shared cache is safe because crypto/tls keys entries by ServerName.
	cache := tls.NewLRUClientSessionCache(32)

	for _, sni := range testThreeSNIs {
		want := issued[sni]

		first := dialSNI(t, addr, sni, pki.pool, cache)
		assertPresentedCert(t, first, want)
		if first.DidResume {
			t.Fatalf("SNI %s: first handshake unexpectedly resumed", sni)
		}

		second := dialSNI(t, addr, sni, pki.pool, cache)
		assertPresentedCert(t, second, want)
		if !second.DidResume {
			t.Fatalf("SNI %s: expected session resumption on second handshake", sni)
		}
	}
}

// TestSNIDynamic_TicketRotationKeepsResumption proves that rotating the STEK
// keeps the previous key around so a ticket issued before the rotation still
// resumes afterwards.
func TestSNIDynamic_TicketRotationKeepsResumption(t *testing.T) {
	pki := newSNIPKI(t)
	sni := testThreeSNIs[0]
	cert := pki.issue(sni)

	store := NewSNICertificateStore()
	if err := store.AddCertificate(sni, cert.tlsCert); err != nil {
		t.Fatal(err)
	}
	rotator, err := NewSessionTicketRotator(4)
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.TLSConfig(nil, rotator)
	addr := startSNITLSServer(t, cfg)
	cache := tls.NewLRUClientSessionCache(8)

	first := dialSNI(t, addr, sni, pki.pool, cache)
	if first.DidResume {
		t.Fatal("first handshake unexpectedly resumed")
	}

	if err := rotator.Rotate(); err != nil {
		t.Fatalf("rotating ticket keys: %v", err)
	}
	if got := len(rotator.Keys()); got != 2 {
		t.Fatalf("expected 2 keys after one rotation, got %d", got)
	}

	second := dialSNI(t, addr, sni, pki.pool, cache)
	assertPresentedCert(t, second, cert)
	if !second.DidResume {
		t.Fatal("session should still resume using the retained previous ticket key")
	}
}

// TestSNIDynamic_DisabledTicketsDoNotResume is a negative control proving the
// resumption assertions above are meaningful.
func TestSNIDynamic_DisabledTicketsDoNotResume(t *testing.T) {
	pki := newSNIPKI(t)
	sni := testThreeSNIs[1]
	cert := pki.issue(sni)

	store := NewSNICertificateStore()
	if err := store.AddCertificate(sni, cert.tlsCert); err != nil {
		t.Fatal(err)
	}
	cfg := store.TLSConfig(nil, nil)
	cfg.SessionTicketsDisabled = true
	addr := startSNITLSServer(t, cfg)
	cache := tls.NewLRUClientSessionCache(8)

	first := dialSNI(t, addr, sni, pki.pool, cache)
	if first.DidResume {
		t.Fatal("first handshake unexpectedly resumed")
	}
	second := dialSNI(t, addr, sni, pki.pool, cache)
	if second.DidResume {
		t.Fatal("session must not resume when session tickets are disabled")
	}
}

func TestSNICertificateStore_Selection(t *testing.T) {
	pki := newSNIPKI(t)
	exact := pki.issue("exact.example.com")
	wild := pki.issue("*.wild.example.com")
	def := pki.issue("default.example.net")

	store := NewSNICertificateStore()
	mustAdd := func(name string, c *issuedCert) {
		t.Helper()
		if err := store.AddCertificate(name, c.tlsCert); err != nil {
			t.Fatalf("adding %s: %v", name, err)
		}
	}
	mustAdd("Exact.Example.COM.", exact) // normalized
	mustAdd("*.wild.example.com", wild)
	mustAdd("*", def)

	ctx := context.Background()
	for _, tc := range []struct {
		name string
		sni  string
		want *issuedCert
		err  bool
	}{
		{name: "exact", sni: "exact.example.com", want: exact},
		{name: "case and trailing dot", sni: "EXACT.example.com.", want: exact},
		{name: "wildcard one label", sni: "a.wild.example.com", want: wild},
		{name: "wildcard second label", sni: "b.wild.example.com", want: wild},
		{name: "unknown falls to default", sni: "anything.else", want: def},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.CertificateForSNI(ctx, tc.sni)
			if tc.err {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Leaf == nil || got.Leaf.SerialNumber.Cmp(tc.want.serial) != 0 {
				t.Fatalf("expected serial %s, got %v", tc.want.serial, got.Leaf)
			}
		})
	}

	// a store with no default reports a recognizable not-found error
	plain := NewSNICertificateStore()
	if err := plain.AddCertificate("only.example.com", pki.issue("only.example.com").tlsCert); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.CertificateForSNI(ctx, "missing.example.com"); !errors.Is(err, ErrSNICertificateNotFound) {
		t.Fatalf("expected ErrSNICertificateNotFound, got %v", err)
	}
}

func TestSNICertificateStore_DynamicFileLoadingAndReload(t *testing.T) {
	pki := newSNIPKI(t)
	dir := t.TempDir()
	sni := "dynamic.test"
	first := pki.issue(sni)
	certFile, keyFile := first.writePair(t, dir, sni)

	store := NewSNICertificateStore()
	store.AddCertificateFile(sni, certFile, keyFile)

	ctx := context.Background()

	// first request lazily loads the file
	got, err := store.CertificateForSNI(ctx, sni)
	if err != nil {
		t.Fatalf("lazy load: %v", err)
	}
	if got.Leaf.SerialNumber.Cmp(first.serial) != 0 {
		t.Fatal("unexpected initial certificate")
	}

	// replace the files and explicitly reload
	rotated := pki.issue(sni)
	rotated.writePair(t, dir, sni)
	if err := store.Reload(ctx, sni); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, err = store.CertificateForSNI(ctx, sni)
	if err != nil {
		t.Fatalf("after reload: %v", err)
	}
	if got.Leaf.SerialNumber.Cmp(rotated.serial) != 0 {
		t.Fatal("reload did not pick up the rotated certificate")
	}

	// a brand-new SNI can be added at runtime
	newSNI := "added-late.test"
	added := pki.issue(newSNI)
	if err := store.AddCertificate(newSNI, added.tlsCert); err != nil {
		t.Fatal(err)
	}
	got, err = store.CertificateForSNI(ctx, newSNI)
	if err != nil {
		t.Fatalf("runtime-added SNI: %v", err)
	}
	if got.Leaf.SerialNumber.Cmp(added.serial) != 0 {
		t.Fatal("runtime-added certificate mismatch")
	}
}

func TestDirectorySNICertificateLoader(t *testing.T) {
	pki := newSNIPKI(t)
	dir := t.TempDir()
	for _, sni := range testThreeSNIs {
		cert := pki.issue(sni)
		cert.writePair(t, dir, sni)
	}

	store := NewSNICertificateStore()
	store.Loader = DirectorySNICertificateLoader{Dir: dir}

	ctx := context.Background()
	for _, sni := range testThreeSNIs {
		got, err := store.CertificateForSNI(ctx, sni)
		if err != nil {
			t.Fatalf("directory load for %s: %v", sni, err)
		}
		if len(got.Leaf.DNSNames) == 0 || got.Leaf.DNSNames[0] != sni {
			t.Fatalf("SNI %s: loader returned %v", sni, got.Leaf.DNSNames)
		}
	}

	// SNI is attacker-controlled and must not escape the directory.
	loader := DirectorySNICertificateLoader{Dir: dir}
	for _, unsafe := range []string{"../evil", "..", "a/../../b", `a\b`, ""} {
		if _, err := loader.LoadCertificateForSNI(ctx, unsafe); err == nil {
			t.Fatalf("expected error for unsafe SNI %q", unsafe)
		}
	}
}

func TestSNICertificateStore_TLSConfigCompatibility(t *testing.T) {
	pki := newSNIPKI(t)
	dynamic := pki.issue(testThreeSNIs[0])
	legacy := pki.issue("legacy.example")
	magic := pki.issue("magic.example")

	store := NewSNICertificateStore()
	if err := store.AddCertificate(testThreeSNIs[0], dynamic.tlsCert); err != nil {
		t.Fatal(err)
	}

	base := &tls.Config{
		Certificates: []tls.Certificate{legacy.tlsCert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		NextProtos:   []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "magic.example" {
				return &magic.tlsCert, nil
			}
			return nil, nil
		},
	}

	cfg := store.TLSConfig(base, nil)

	// existing settings survive the clone
	if len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" {
		t.Fatalf("NextProtos not preserved: %v", cfg.NextProtos)
	}
	if len(cfg.CipherSuites) != 1 {
		t.Fatalf("CipherSuites not preserved: %v", cfg.CipherSuites)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("static Certificates not preserved: %d", len(cfg.Certificates))
	}
	// the original config is not rewired
	if base.GetCertificate == nil {
		t.Fatal("base GetCertificate must remain set")
	}

	ctxHello := func(sni string) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{ServerName: sni}
	}

	// managed SNI wins
	got, err := cfg.GetCertificate(ctxHello(testThreeSNIs[0]))
	if err != nil {
		t.Fatalf("managed SNI: %v", err)
	}
	if got.Leaf.SerialNumber.Cmp(dynamic.serial) != 0 {
		t.Fatal("managed SNI did not return dynamic certificate")
	}

	// unmanaged SNI chains to the pre-existing GetCertificate
	got, err = cfg.GetCertificate(ctxHello("magic.example"))
	if err != nil {
		t.Fatalf("chained GetCertificate: %v", err)
	}
	if got == nil || got.Leaf.SerialNumber.Cmp(magic.serial) != 0 {
		t.Fatal("expected chained CertMagic-style certificate")
	}

	// unmanaged SNI with no callback certificate returns nil,nil so crypto/tls
	// falls back to the preserved static Certificates.
	got, err = cfg.GetCertificate(ctxHello("legacy.example"))
	if err != nil {
		t.Fatalf("static fallback path: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil to defer to static certificates, got %v", got.Leaf)
	}
}

func TestSessionTicketRotator_KeysAndLifecycle(t *testing.T) {
	r, err := NewSessionTicketRotator(3)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.Keys()); got != 1 {
		t.Fatalf("expected one initial key, got %d", got)
	}

	initial := r.Keys()[0]
	if err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	if got := r.Keys(); len(got) != 2 || got[0] == initial {
		t.Fatalf("rotation did not prepend a new primary: len=%d", len(got))
	}

	_ = r.Rotate()
	keys := r.Keys()
	if len(keys) != 3 {
		t.Fatalf("expected max of 3 keys, got %d", len(keys))
	}

	// next rotation evicts the oldest (initial) key while staying at capacity
	if err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	keys = r.Keys()
	if len(keys) != 3 {
		t.Fatalf("expected capacity to remain 3, got %d", len(keys))
	}
	for _, key := range keys {
		if key == initial {
			t.Fatal("oldest ticket key should have been evicted")
		}
	}

	// periodic rotation advances the key set
	before := r.Keys()[0]
	r.Start(10 * time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r.Keys()[0] != before {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r.Keys()[0] == before {
		t.Fatal("background rotation did not run")
	}
	r.Stop()

	// Stop is idempotent and a second Start can be stopped cleanly.
	r.Stop()
	r.Start(time.Hour)
	r.Stop()
}

// TestSNICertificateStore_Concurrent exercises parallel handshakes/access.
func TestSNICertificateStore_Concurrent(t *testing.T) {
	pki := newSNIPKI(t)
	store := NewSNICertificateStore()
	for _, sni := range testThreeSNIs {
		if err := store.AddCertificate(sni, pki.issue(sni).tlsCert); err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for n := range 50 {
				sni := testThreeSNIs[(worker+n)%len(testThreeSNIs)]
				if _, err := store.CertificateForSNI(ctx, sni); err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
}

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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
)

// ErrSNICertificateNotFound is returned when an SNI name has no certificate
// registered in an SNICertificateStore and no dynamic loader can supply one.
// Callers that compose another GetCertificate function can use errors.Is to
// decide whether to fall through to an existing TLS configuration.
var ErrSNICertificateNotFound = errors.New("no dynamic certificate for SNI")

// SNICertificateLoader loads a certificate for a Server Name Indication
// (SNI) value on demand. Implementations may fetch certificates from the
// local disk, a secret store, or an internal API. The returned certificate
// must contain a usable private key.
type SNICertificateLoader interface {
	LoadCertificateForSNI(ctx context.Context, serverName string) (tls.Certificate, error)
}

// SNICertificateStore selects certificates by SNI during a TLS handshake and
// can load them dynamically. It is safe for concurrent use.
//
// Names are matched case-insensitively after normalization (lower-cased and
// without a trailing dot). Exact names take priority, then the most specific
// wildcard pattern (for example "*.example.com"), then an optional default
// certificate registered as "" or "*".
//
// Certificates added as PEM or parsed key pairs are served directly.
// Certificates added as cert/key file paths are loaded lazily on the first
// handshake that needs them and may be reloaded explicitly with Reload or
// automatically after FileReloadInterval. A Loader can supply certificates
// for SNI names that were not registered explicitly, which allows new hosts
// to be served without reconfiguring or restarting Caddy.
type SNICertificateStore struct {
	// Loader, if set, is called for SNI names that have no explicit
	// certificate registration. Certificates it returns are cached as
	// exact-name entries and refreshed according to DynamicReloadInterval.
	Loader SNICertificateLoader

	// FileReloadInterval limits how often file-backed entries are reloaded
	// from disk when their certificate is requested. Zero means file
	// entries are only loaded once and reloaded by calling Reload.
	FileReloadInterval time.Duration

	// DynamicReloadInterval limits how often certificates obtained from
	// Loader are fetched again. Zero means they are cached indefinitely.
	DynamicReloadInterval time.Duration

	mu       sync.RWMutex
	exact    map[string]*sniCertificateEntry
	wildcard map[string]*sniCertificateEntry
	fallback *sniCertificateEntry
}

// NewSNICertificateStore returns an initialized, empty SNI certificate store.
func NewSNICertificateStore() *SNICertificateStore {
	return &SNICertificateStore{
		exact:    make(map[string]*sniCertificateEntry),
		wildcard: make(map[string]*sniCertificateEntry),
	}
}

// AddCertificate registers an already-parsed key pair for the given SNI name.
// The name may be an exact host, a wildcard pattern, or ""/"*" for the
// default certificate.
func (s *SNICertificateStore) AddCertificate(name string, cert tls.Certificate) error {
	if cert.PrivateKey == nil {
		return fmt.Errorf("adding certificate for %q: missing private key", name)
	}
	if cert.Leaf == nil {
		// Leaf is optional for crypto/tls, but parsing it now lets us validate
		// the pair and makes certificate assertions and selection reliable.
		leaf, err := parseCertificateLeaf(&cert)
		if err != nil {
			return fmt.Errorf("adding certificate for %q: %w", name, err)
		}
		cert.Leaf = leaf
	}
	s.setEntry(name, &sniCertificateEntry{cert: &cert})
	return nil
}

// AddCertificatePEM parses and registers a PEM-encoded certificate chain and
// private key for the given SNI name.
func (s *SNICertificateStore) AddCertificatePEM(name string, certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("parsing key pair for %q: %w", name, err)
	}
	return s.AddCertificate(name, cert)
}

// AddCertificateFile registers certFile and keyFile for the given SNI name.
// The key pair is not read until the first handshake for that name, so files
// may be provisioned after Caddy starts. Replacing the files and calling
// Reload (or waiting for FileReloadInterval) rotates the served certificate.
func (s *SNICertificateStore) AddCertificateFile(name, certFile, keyFile string) {
	entry := &sniCertificateEntry{certFile: certFile, keyFile: keyFile}
	entry.load = entry.loadFiles
	s.setEntry(name, entry)
}

// setEntry classifies the name and stores the entry in the right index.
func (s *SNICertificateStore) setEntry(name string, entry *sniCertificateEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch normalized := NormalizeSNI(name); {
	case name == "" || normalized == "*":
		s.fallback = entry
	case strings.Contains(normalized, "*"):
		s.wildcard[normalized] = entry
	default:
		s.exact[normalized] = entry
	}
}

// Remove deletes any registration associated with name. It returns true if an
// entry existed. Dynamically loaded entries cached from Loader are removed by
// the same method.
func (s *SNICertificateStore) Remove(name string) bool {
	normalized := NormalizeSNI(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" || normalized == "*" {
		existed := s.fallback != nil
		s.fallback = nil
		return existed
	}
	if strings.Contains(normalized, "*") {
		_, ok := s.wildcard[normalized]
		delete(s.wildcard, normalized)
		return ok
	}
	_, ok := s.exact[normalized]
	delete(s.exact, normalized)
	return ok
}

// Reload forces the registration for name to load its certificate again. It
// has no effect on purely in-memory certificates. If name is empty, every
// file-backed or dynamically loaded entry is refreshed on its next request.
func (s *SNICertificateStore) Reload(ctx context.Context, name string) error {
	if name != "" {
		entry := s.entryFor(NormalizeSNI(name))
		if entry == nil || entry.load == nil {
			return nil
		}
		_, err := entry.get(ctx, true, 0)
		return err
	}

	s.mu.RLock()
	entries := make([]*sniCertificateEntry, 0, len(s.exact)+len(s.wildcard)+1)
	for _, entry := range s.exact {
		entries = append(entries, entry)
	}
	for _, entry := range s.wildcard {
		entries = append(entries, entry)
	}
	if s.fallback != nil {
		entries = append(entries, s.fallback)
	}
	s.mu.RUnlock()

	for _, entry := range entries {
		if entry.load == nil {
			continue
		}
		if _, err := entry.get(ctx, true, 0); err != nil {
			return err
		}
	}
	return nil
}

// GetCertificate implements the standard library's
// tls.Config.GetCertificate callback.
func (s *SNICertificateStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, errors.New("nil client hello")
	}
	return s.CertificateForSNI(hello.Context(), hello.ServerName)
}

// CertificateForSNI resolves and loads the certificate for serverName.
func (s *SNICertificateStore) CertificateForSNI(ctx context.Context, serverName string) (*tls.Certificate, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	name := NormalizeSNI(serverName)

	if entry := s.entryFor(name); entry != nil {
		return entry.get(ctx, false, s.entryTTL(entry))
	}

	// no explicit registration; try the dynamic backend and cache the result
	s.mu.RLock()
	loader := s.Loader
	s.mu.RUnlock()
	if loader == nil {
		return nil, fmt.Errorf("%w: %q", ErrSNICertificateNotFound, serverName)
	}

	cert, err := loader.LoadCertificateForSNI(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("loading certificate for SNI %q: %w", name, err)
	}
	if cert.PrivateKey == nil {
		return nil, fmt.Errorf("loader returned certificate without private key for SNI %q", name)
	}
	entry := &sniCertificateEntry{
		cert: &cert,
		load: func(ctx context.Context) (*tls.Certificate, error) {
			loaded, err := loader.LoadCertificateForSNI(ctx, name)
			if err != nil {
				return nil, err
			}
			return &loaded, nil
		},
		dynamic: true,
		loaded:  time.Now(),
	}
	s.mu.Lock()
	// a concurrent handshake may have populated this name first; keep theirs
	if existing := s.exact[name]; existing != nil {
		entry = existing
	} else {
		s.exact[name] = entry
	}
	s.mu.Unlock()

	return entry.get(ctx, false, s.entryTTL(entry))
}

// entryTTL resolves the configured refresh interval for an entry's origin.
func (s *SNICertificateStore) entryTTL(entry *sniCertificateEntry) time.Duration {
	switch {
	case entry == nil || entry.load == nil:
		return 0
	case entry.dynamic:
		return s.DynamicReloadInterval
	default:
		return s.FileReloadInterval
	}
}

// entryFor returns the best matching entry for a normalized name: exact, then
// most specific wildcard, then the default.
func (s *SNICertificateStore) entryFor(name string) *sniCertificateEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if entry := s.exact[name]; entry != nil {
		return entry
	}

	// Choose the longest matching pattern; for the single-label wildcard
	// convention this is also the most specific match.
	bestPattern := ""
	var best *sniCertificateEntry
	for pattern, entry := range s.wildcard {
		if !certmagic.MatchWildcard(name, pattern) {
			continue
		}
		if best == nil || len(pattern) > len(bestPattern) {
			bestPattern = pattern
			best = entry
		}
	}
	if best != nil {
		return best
	}

	return s.fallback
}

// Len returns the number of explicit registrations, including wildcard and
// default entries. Dynamically cached certificates are counted as exact names.
func (s *SNICertificateStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.exact) + len(s.wildcard)
	if s.fallback != nil {
		n++
	}
	return n
}

// TLSConfig returns a standard-library TLS configuration that serves
// certificates from s by SNI and rotates session ticket keys with tickets.
//
// If base is non-nil it is cloned, so existing settings (cipher suites,
// client CAs, ALPN, static certificates, and a pre-existing GetCertificate
// function such as CertMagic's) are preserved. Names not managed by s are
// delegated to base's GetCertificate, and if that is unset the standard
// library still evaluates base's static Certificates. If base is nil, safe
// TLS 1.2+ defaults are used.
//
// When tickets is non-nil, its keys are installed on the returned config and
// kept up to date across rotations. Pass nil to leave session ticket settings
// inherited from base untouched.
func (s *SNICertificateStore) TLSConfig(base *tls.Config, tickets *SessionTicketRotator) *tls.Config {
	var cfg *tls.Config
	var baseGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if base != nil {
		cfg = base.Clone()
		baseGetCertificate = base.GetCertificate
	} else {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	cfg.GetCertificate = s.composeGetCertificate(baseGetCertificate)

	if tickets != nil {
		cfg.SessionTicketsDisabled = false
		tickets.Register(cfg)
	}

	return cfg
}

// composeGetCertificate chains SNI selection to a pre-existing callback.
func (s *SNICertificateStore) composeGetCertificate(
	next func(*tls.ClientHelloInfo) (*tls.Certificate, error),
) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := s.GetCertificate(hello)
		if err == nil && cert != nil {
			return cert, nil
		}

		if next != nil {
			nextCert, nextErr := next(hello)
			if nextErr == nil && nextCert != nil {
				return nextCert, nil
			}
			// surface a concrete selection/load error before the fallback's
			if err != nil && !errors.Is(err, ErrSNICertificateNotFound) {
				return nil, err
			}
			if nextErr != nil {
				return nil, nextErr
			}
			return nextCert, nil
		}

		// Returning nil, nil lets crypto/tls fall back to the static
		// Certificates carried by the cloned config, if any.
		if err != nil && errors.Is(err, ErrSNICertificateNotFound) {
			return nil, nil
		}
		return nil, err
	}
}

// NormalizeSNI canonicalizes an SNI value for map lookup: it trims
// whitespace, lower-cases it, strips a trailing dot, and removes any port.
func NormalizeSNI(name string) string {
	name = strings.TrimSpace(name)
	if host, _, err := net.SplitHostPort(name); err == nil {
		name = host
	}
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".")
	return name
}

// sniCertificateEntry is a concurrency-safe, optionally lazy certificate.
type sniCertificateEntry struct {
	cert     *tls.Certificate
	load     func(context.Context) (*tls.Certificate, error)
	certFile string
	keyFile  string
	dynamic  bool

	mu     sync.Mutex
	loaded time.Time
}

// get returns the cached certificate, loading or refreshing it when needed.
// A previously good certificate is retained if a background refresh fails.
func (e *sniCertificateEntry) get(ctx context.Context, force bool, ttl time.Duration) (*tls.Certificate, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	fresh := e.cert != nil && (ttl <= 0 || time.Since(e.loaded) < ttl)
	if !force && fresh {
		return e.cert, nil
	}
	if e.load == nil {
		return e.cert, nil
	}

	cert, err := e.load(ctx)
	if err != nil {
		if e.cert != nil {
			return e.cert, nil
		}
		return nil, err
	}
	if cert.PrivateKey == nil {
		if e.cert != nil {
			return e.cert, nil
		}
		return nil, errors.New("loaded certificate has no private key")
	}
	e.cert = cert
	e.loaded = time.Now()
	return e.cert, nil
}

// loadFiles reads and parses the configured cert/key pair from disk.
func (e *sniCertificateEntry) loadFiles(ctx context.Context) (*tls.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(e.certFile)
	if err != nil {
		return nil, fmt.Errorf("reading certificate file: %w", err)
	}
	keyPEM, err := os.ReadFile(e.keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing key pair: %w", err)
	}
	if cert.Leaf == nil {
		leaf, err := parseCertificateLeaf(&cert)
		if err != nil {
			return nil, err
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

// DirectorySNICertificateLoader maps an SNI host name to PEM files inside a
// directory. By default it reads "<dir>/<sni>.crt" and "<dir>/<sni>.key";
// set CertExtension or KeyExtension to use other suffixes (for example
// ".pem"). Only a single, safe file-name segment is accepted, because SNI is
// attacker-controlled and must never be able to escape the directory.
type DirectorySNICertificateLoader struct {
	// Dir is the directory containing the certificate and key files.
	Dir string

	// CertExtension defaults to ".crt".
	CertExtension string

	// KeyExtension defaults to ".key".
	KeyExtension string
}

// LoadCertificateForSNI implements SNICertificateLoader.
func (d DirectorySNICertificateLoader) LoadCertificateForSNI(ctx context.Context, serverName string) (tls.Certificate, error) {
	name := NormalizeSNI(serverName)
	if name == "" {
		return tls.Certificate{}, errors.New("empty SNI")
	}
	// Reject path separators, traversal, and anything that is not a single
	// base name before joining it with the configured directory.
	if name == "." || name == ".." || filepath.Base(name) != name ||
		strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return tls.Certificate{}, fmt.Errorf("unsafe SNI file name %q", serverName)
	}
	if err := ctx.Err(); err != nil {
		return tls.Certificate{}, err
	}

	certExt := d.CertExtension
	if certExt == "" {
		certExt = ".crt"
	}
	keyExt := d.KeyExtension
	if keyExt == "" {
		keyExt = ".key"
	}

	base := filepath.Join(d.Dir, name)
	certPEM, err := os.ReadFile(base + certExt)
	if err != nil {
		if os.IsNotExist(err) {
			return tls.Certificate{}, fmt.Errorf("%w: %q", ErrSNICertificateNotFound, name)
		}
		return tls.Certificate{}, fmt.Errorf("reading certificate for %q: %w", name, err)
	}
	keyPEM, err := os.ReadFile(base + keyExt)
	if err != nil {
		if os.IsNotExist(err) {
			return tls.Certificate{}, fmt.Errorf("%w: %q", ErrSNICertificateNotFound, name)
		}
		return tls.Certificate{}, fmt.Errorf("reading key for %q: %w", name, err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing key pair for %q: %w", name, err)
	}
	return cert, nil
}

// SessionTicketRotator manages a set of TLS session ticket encryption keys
// (STEKs), periodically introducing a fresh primary key while retaining
// previous keys long enough to decrypt tickets issued earlier. The overlap is
// what allows session resumption to continue across a rotation.
//
// It reuses SessionTicketService.RotateSTEKs for key generation, eviction,
// and zeroization, and can keep any number of standard-library tls.Config
// values updated. It is safe for concurrent use.
type SessionTicketRotator struct {
	// MaxKeys is the maximum number of STEKs retained at once. Default 4.
	MaxKeys int

	// RotationInterval is used by Start when no interval is supplied.
	// Default 12h, matching SessionTicketService.
	RotationInterval time.Duration

	stek SessionTicketService

	mu      sync.Mutex
	keys    [][32]byte
	configs map[*tls.Config]struct{}
	ticker  *time.Ticker
	stopCh  chan struct{}
	done    chan struct{}
}

// NewSessionTicketRotator creates a rotator with one random primary key.
func NewSessionTicketRotator(maxKeys int) (*SessionTicketRotator, error) {
	if maxKeys <= 0 {
		maxKeys = defaultMaxSTEKs
	}
	r := &SessionTicketRotator{
		MaxKeys: maxKeys,
		stek:    SessionTicketService{MaxKeys: maxKeys},
		configs: make(map[*tls.Config]struct{}),
	}
	initial, err := r.stek.generateSTEK()
	if err != nil {
		return nil, fmt.Errorf("generating initial session ticket key: %w", err)
	}
	r.keys = [][32]byte{initial}
	return r, nil
}

// Register installs the current ticket keys on cfg and keeps them updated on
// every Rotate. It is idempotent for the same config pointer.
func (r *SessionTicketRotator) Register(cfg *tls.Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg.SessionTicketsDisabled = false
	cfg.SetSessionTicketKeys(cloneSTEKs(r.keys))
	r.configs[cfg] = struct{}{}
}

// Unregister stops updating cfg. It does not alter cfg's current keys.
func (r *SessionTicketRotator) Unregister(cfg *tls.Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.configs, cfg)
}

// Rotate generates a new primary key, prepends it, evicts and zeroizes the
// oldest key beyond MaxKeys, and installs the resulting key set on every
// registered config.
func (r *SessionTicketRotator) Rotate() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	keys, err := r.stek.RotateSTEKs(r.keys)
	if err != nil {
		return err
	}
	r.keys = keys
	keyCopy := cloneSTEKs(keys)
	for cfg := range r.configs {
		cfg.SetSessionTicketKeys(keyCopy)
	}
	return nil
}

// Keys returns a copy of the active keys, primary first.
func (r *SessionTicketRotator) Keys() [][32]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneSTEKs(r.keys)
}

// Start begins periodic rotation. A non-positive interval uses
// r.RotationInterval and then the Caddy default. Start is a no-op if the
// rotator is already running.
func (r *SessionTicketRotator) Start(interval time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopCh != nil {
		return
	}
	if interval <= 0 {
		interval = r.RotationInterval
	}
	if interval <= 0 {
		interval = defaultSTEKRotationInterval
	}
	r.ticker = time.NewTicker(interval)
	r.stopCh = make(chan struct{})
	r.done = make(chan struct{})
	go r.run(r.ticker.C, r.stopCh, r.done)
}

// run rotates on each tick until stopCh closes, then closes done.
func (r *SessionTicketRotator) run(ticks <-chan time.Time, stopCh <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	for {
		select {
		case <-ticks:
			_ = r.Rotate()
		case <-stopCh:
			return
		}
	}
}

// Stop ends periodic rotation and waits for the goroutine to exit.
func (r *SessionTicketRotator) Stop() {
	r.mu.Lock()
	stopCh := r.stopCh
	done := r.done
	ticker := r.ticker
	r.stopCh = nil
	r.ticker = nil
	r.mu.Unlock()

	if stopCh == nil {
		return
	}
	if ticker != nil {
		ticker.Stop()
	}
	close(stopCh)
	if done != nil {
		<-done
	}
}

// cloneSTEKs returns an independent copy of keys.
func cloneSTEKs(keys [][32]byte) [][32]byte {
	if keys == nil {
		return nil
	}
	out := make([][32]byte, len(keys))
	copy(out, keys)
	return out
}

// parseCertificateLeaf parses the first DER certificate in a key pair.
func parseCertificateLeaf(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errors.New("certificate contains no DER blocks")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}
	return leaf, nil
}

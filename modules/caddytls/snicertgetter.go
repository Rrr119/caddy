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
	"errors"
	"fmt"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(SNICertGetter{})
}

// SNICertGetter is a certmagic.Manager (the tls.get_certificate.sni module)
// that selects and dynamically loads certificates by SNI.
//
// It makes SNICertificateStore available through Caddy's existing TLS
// automation and connection policy machinery: configure it in an automation
// policy's get_certificate list (or the tls Caddyfile directive) and Caddy
// will call it during handshakes alongside its normal certificate management.
// Names it does not serve return nil, nil so the next manager or CertMagic's
// normal selection can handle them.
type SNICertGetter struct {
	// Directory, if set, loads "<directory>/<sni>.crt" and
	// "<directory>/<sni>.key" for any SNI not listed in Certificates.
	Directory string `json:"directory,omitempty"`

	// CertExtension overrides the default ".crt" suffix used with Directory.
	CertExtension string `json:"cert_extension,omitempty"`

	// KeyExtension overrides the default ".key" suffix used with Directory.
	KeyExtension string `json:"key_extension,omitempty"`

	// ReloadInterval optionally enables periodic file/dynamic refresh.
	ReloadInterval caddy.Duration `json:"reload_interval,omitempty"`

	// Certificates maps an SNI name (exact or wildcard, or "*" default) to
	// its PEM or cert/key file source.
	Certificates map[string]SNICertificateBinding `json:"certificates,omitempty"`

	store *SNICertificateStore
}

// SNICertificateBinding is one SNI certificate source for SNICertGetter.
type SNICertificateBinding struct {
	// CertFile and KeyFile are lazy-loaded paths to PEM files.
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`

	// CertPEM and KeyPEM are inline PEM-encoded chain and private key.
	CertPEM string `json:"cert_pem,omitempty"`
	KeyPEM  string `json:"key_pem,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (SNICertGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.sni",
		New: func() caddy.Module { return new(SNICertGetter) },
	}
}

// Provision builds the underlying SNI certificate store.
func (g *SNICertGetter) Provision(_ caddy.Context) error {
	store, err := g.buildStore()
	if err != nil {
		return err
	}
	g.store = store
	return nil
}

// buildStore validates configuration and constructs the store.
func (g *SNICertGetter) buildStore() (*SNICertificateStore, error) {
	store := NewSNICertificateStore()

	if g.Directory != "" {
		store.Loader = DirectorySNICertificateLoader{
			Dir:           g.Directory,
			CertExtension: g.CertExtension,
			KeyExtension:  g.KeyExtension,
		}
	}
	if g.ReloadInterval > 0 {
		interval := time.Duration(g.ReloadInterval)
		store.FileReloadInterval = interval
		store.DynamicReloadInterval = interval
	}

	for sni, binding := range g.Certificates {
		hasPEM := binding.CertPEM != "" || binding.KeyPEM != ""
		hasFiles := binding.CertFile != "" || binding.KeyFile != ""
		switch {
		case hasPEM && hasFiles:
			return nil, fmt.Errorf("certificate for %q cannot set both PEM and file sources", sni)
		case hasPEM:
			if binding.CertPEM == "" || binding.KeyPEM == "" {
				return nil, fmt.Errorf("certificate for %q requires both cert_pem and key_pem", sni)
			}
			if err := store.AddCertificatePEM(sni, []byte(binding.CertPEM), []byte(binding.KeyPEM)); err != nil {
				return nil, err
			}
		case hasFiles:
			if binding.CertFile == "" || binding.KeyFile == "" {
				return nil, fmt.Errorf("certificate for %q requires both cert_file and key_file", sni)
			}
			store.AddCertificateFile(sni, binding.CertFile, binding.KeyFile)
		default:
			return nil, fmt.Errorf("certificate for %q must define a PEM or file source", sni)
		}
	}

	return store, nil
}

// GetCertificate implements certmagic.Manager. Unknown SNI names return
// (nil, nil) to pass through to subsequent certificate sources.
func (g *SNICertGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if g.store == nil {
		return nil, errors.New("sni certificate getter is not provisioned")
	}
	if hello == nil {
		return nil, errors.New("nil client hello")
	}
	cert, err := g.store.CertificateForSNI(ctx, hello.ServerName)
	if errors.Is(err, ErrSNICertificateNotFound) {
		return nil, nil
	}
	return cert, err
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//	get_certificate sni [<directory>] {
//	    directory        <path>
//	    cert_extension   <.ext>
//	    key_extension    <.ext>
//	    reload_interval  <duration>
//	    cert <sni> <cert_file> <key_file>
//	}
func (g *SNICertGetter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume module name ("sni")

	// an optional single positional argument is the directory
	if d.NextArg() {
		g.Directory = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		option := d.Val()
		switch option {
		case "directory":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			g.Directory = args[0]

		case "cert_extension":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			g.CertExtension = args[0]

		case "key_extension":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			g.KeyExtension = args[0]

		case "reload_interval":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(args[0])
			if err != nil {
				return d.Errf("parsing reload_interval %q: %v", args[0], err)
			}
			g.ReloadInterval = caddy.Duration(dur)

		case "cert":
			args := d.RemainingArgs()
			if len(args) != 3 {
				return d.Errf("usage: cert <sni> <cert_file> <key_file>")
			}
			if g.Certificates == nil {
				g.Certificates = make(map[string]SNICertificateBinding)
			}
			sni := NormalizeSNI(args[0])
			if _, exists := g.Certificates[sni]; exists {
				return d.Errf("duplicate certificate for SNI %q", sni)
			}
			g.Certificates[sni] = SNICertificateBinding{
				CertFile: args[1],
				KeyFile:  args[2],
			}

		default:
			return d.Errf("unrecognized subdirective: %s", option)
		}

		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option %q: nested blocks are not supported", "sni", option)
		}
	}

	return nil
}

// Interface guards.
var (
	_ caddy.Module          = (*SNICertGetter)(nil)
	_ certmagic.Manager     = (*SNICertGetter)(nil)
	_ caddy.Provisioner     = (*SNICertGetter)(nil)
	_ caddyfile.Unmarshaler = (*SNICertGetter)(nil)
)

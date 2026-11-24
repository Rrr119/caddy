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
	"fmt"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestSNICertGetter_Registered(t *testing.T) {
	info, err := caddy.GetModule("tls.get_certificate.sni")
	if err != nil {
		t.Fatalf("module not registered: %v", err)
	}
	mod := info.New()
	if _, ok := mod.(*SNICertGetter); !ok {
		t.Fatalf("New() returned %T, want *SNICertGetter", mod)
	}
}

func TestSNICertGetter_CaddyfileDirectory(t *testing.T) {
	pki := newSNIPKI(t)
	dir := t.TempDir()
	issued := make(map[string]*issuedCert)
	for _, sni := range testThreeSNIs {
		cert := pki.issue(sni)
		issued[sni] = cert
		cert.writePair(t, dir, sni)
	}

	input := fmt.Sprintf(`sni %s {
		reload_interval 2s
	}`, dir)

	var getter SNICertGetter
	if err := getter.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if getter.Directory != dir {
		t.Fatalf("directory mismatch: %q", getter.Directory)
	}
	if getter.ReloadInterval != caddy.Duration(2*time.Second) {
		t.Fatalf("reload interval mismatch: %v", getter.ReloadInterval)
	}
	if err := getter.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	ctx := context.Background()
	for _, sni := range testThreeSNIs {
		cert, err := getter.GetCertificate(ctx, &tls.ClientHelloInfo{ServerName: sni})
		if err != nil {
			t.Fatalf("GetCertificate(%s): %v", sni, err)
		}
		if cert == nil || cert.Leaf == nil || cert.Leaf.SerialNumber.Cmp(issued[sni].serial) != 0 {
			t.Fatalf("GetCertificate(%s) returned the wrong certificate", sni)
		}
	}

	// names the directory cannot serve are a pass-thru, not an error
	cert, err := getter.GetCertificate(ctx, &tls.ClientHelloInfo{ServerName: "absent.test"})
	if err != nil {
		t.Fatalf("unknown SNI should pass through, got error: %v", err)
	}
	if cert != nil {
		t.Fatalf("unknown SNI should return nil certificate, got %v", cert.Leaf)
	}
}

func TestSNICertGetter_CaddyfileExplicitCert(t *testing.T) {
	pki := newSNIPKI(t)
	dir := t.TempDir()
	sni := testThreeSNIs[2]
	want := pki.issue(sni)
	certFile, keyFile := want.writePair(t, dir, sni)

	input := fmt.Sprintf(`sni {
		cert %s %s %s
	}`, sni, certFile, keyFile)

	var getter SNICertGetter
	if err := getter.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(getter.Certificates) != 1 {
		t.Fatalf("expected one binding, got %d", len(getter.Certificates))
	}
	if err := getter.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	cert, err := getter.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: sni})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil || cert.Leaf.SerialNumber.Cmp(want.serial) != 0 {
		t.Fatal("explicit cert binding returned the wrong certificate")
	}
}

func TestSNICertGetter_CaddyfileErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{name: "unknown subdirective", input: `sni { bogus value }`},
		{name: "cert missing key", input: "sni {\n\tcert a.test /tmp/cert\n}"},
		{name: "bad duration", input: `sni { reload_interval not-a-duration }`},
		{name: "duplicate sni", input: `sni {
			cert a.test /tmp/a.crt /tmp/a.key
			cert a.test /tmp/b.crt /tmp/b.key
		}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var getter SNICertGetter
			if err := getter.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input)); err == nil {
				t.Fatal("expected parse error, got nil")
			}
		})
	}
}

func TestSNICertGetter_BuildValidation(t *testing.T) {
	pki := newSNIPKI(t)
	want := pki.issue("pem.test")

	t.Run("both pem and files", func(t *testing.T) {
		g := SNICertGetter{Certificates: map[string]SNICertificateBinding{
			"x.test": {CertPEM: string(want.certPEM), CertFile: "/tmp/x"},
		}}
		if _, err := g.buildStore(); err == nil {
			t.Fatal("expected conflict error")
		}
	})

	t.Run("valid pem", func(t *testing.T) {
		g := SNICertGetter{Certificates: map[string]SNICertificateBinding{
			"pem.test": {CertPEM: string(want.certPEM), KeyPEM: string(want.keyPEM)},
		}}
		store, err := g.buildStore()
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		cert, err := store.CertificateForSNI(context.Background(), "pem.test")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if cert.Leaf.SerialNumber.Cmp(want.serial) != 0 {
			t.Fatal("PEM binding mismatch")
		}
	})
}

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

package caddyhttp

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"slices"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestMatchClientCert(t *testing.T) {
	trueVal, falseVal := true, false

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:         "client-a",
			Organization:       []string{"Edge-Gateway", "Ops"},
			OrganizationalUnit: []string{"team-blue"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test CA Org"},
		},
		DNSNames:       []string{"client-a.example.com"},
		EmailAddresses: []string{"client-a@example.com"},
	}

	reqWithCert := &http.Request{TLS: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}}
	reqWithUnverifiedCert := &http.Request{TLS: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
	}}
	reqWithoutCert := &http.Request{TLS: &tls.ConnectionState{}}
	reqWithoutTLS := &http.Request{}

	for i, tc := range []struct {
		matcher MatchClientCert
		req     *http.Request
		expect  bool
	}{
		{matcher: MatchClientCert{}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{}, req: reqWithoutCert, expect: true},
		{matcher: MatchClientCert{}, req: reqWithoutTLS, expect: false},
		{matcher: MatchClientCert{Verified: &trueVal}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{Verified: &trueVal}, req: reqWithUnverifiedCert, expect: false},
		{matcher: MatchClientCert{Verified: &trueVal}, req: reqWithoutCert, expect: false},
		{matcher: MatchClientCert{Verified: &falseVal}, req: reqWithoutCert, expect: true},
		{matcher: MatchClientCert{Verified: &falseVal}, req: reqWithUnverifiedCert, expect: true},
		{matcher: MatchClientCert{Verified: &falseVal}, req: reqWithCert, expect: false},
		{matcher: MatchClientCert{SubjectCommonName: []string{"client-a"}}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{SubjectCommonName: []string{"client-b"}}, req: reqWithCert, expect: false},
		{matcher: MatchClientCert{SubjectCommonName: []string{"client-b", "client-a"}}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{SubjectOrganization: []string{"Edge-Gateway"}}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{SubjectOrganization: []string{"Other-Org"}}, req: reqWithCert, expect: false},
		{matcher: MatchClientCert{SubjectOrganizationalUnit: []string{"team-blue"}}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{SubjectOrganizationalUnit: []string{"team-red"}}, req: reqWithCert, expect: false},
		{matcher: MatchClientCert{IssuerCommonName: []string{"Test Root CA"}}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{IssuerCommonName: []string{"Other CA"}}, req: reqWithCert, expect: false},
		{matcher: MatchClientCert{IssuerOrganization: []string{"Test CA Org"}}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{SerialNumber: []string{"12345"}}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{SerialNumber: []string{"99999"}}, req: reqWithCert, expect: false},
		{matcher: MatchClientCert{SANDNSNames: []string{"client-a.example.com"}}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{SANDNSNames: []string{"other.example.com"}}, req: reqWithCert, expect: false},
		{matcher: MatchClientCert{SANEmailAddresses: []string{"client-a@example.com"}}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{SANEmailAddresses: []string{"other@example.com"}}, req: reqWithCert, expect: false},
		// field matchers require a presented certificate
		{matcher: MatchClientCert{SubjectCommonName: []string{"client-a"}}, req: reqWithoutCert, expect: false},
		{matcher: MatchClientCert{SubjectCommonName: []string{"client-a"}}, req: reqWithoutTLS, expect: false},
		// multiple fields are AND'ed together
		{matcher: MatchClientCert{
			Verified:                  &trueVal,
			SubjectOrganization:       []string{"Edge-Gateway"},
			SubjectOrganizationalUnit: []string{"team-blue"},
		}, req: reqWithCert, expect: true},
		{matcher: MatchClientCert{
			Verified:                  &trueVal,
			SubjectOrganization:       []string{"Edge-Gateway"},
			SubjectOrganizationalUnit: []string{"team-red"},
		}, req: reqWithCert, expect: false},
	} {
		actual := tc.matcher.Match(tc.req)
		if actual != tc.expect {
			t.Errorf("Test %d: expected %v, got %v (matcher: %+v)", i, tc.expect, actual, tc.matcher)
		}
	}
}

func TestMatchClientCertUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		input   string
		expect  MatchClientCert
		wantErr bool
	}{
		{
			input: `client_cert {
				verified
				subject_organization Edge-Gateway Ops
				subject_organizational_unit team-blue
			}`,
			expect: MatchClientCert{
				Verified:                  new(true),
				SubjectOrganization:       []string{"Edge-Gateway", "Ops"},
				SubjectOrganizationalUnit: []string{"team-blue"},
			},
		},
		{
			input: `client_cert {
				verified false
			}`,
			expect: MatchClientCert{Verified: new(false)},
		},
		{
			input: `client_cert {
				subject_common_name client-a
				issuer_common_name Root-CA
				serial_number 12345
				san_dns_names client-a.example.com
				san_email_addresses client-a@example.com
			}`,
			expect: MatchClientCert{
				SubjectCommonName: []string{"client-a"},
				IssuerCommonName:  []string{"Root-CA"},
				SerialNumber:      []string{"12345"},
				SANDNSNames:       []string{"client-a.example.com"},
				SANEmailAddresses: []string{"client-a@example.com"},
			},
		},
		{
			input:   `client_cert unexpected_arg`,
			wantErr: true,
		},
		{
			input: `client_cert {
				verified bogus
			}`,
			wantErr: true,
		},
		{
			input: `client_cert {
				subject_common_name
			}`,
			wantErr: true,
		},
		{
			input: `client_cert {
				not_a_real_option value
			}`,
			wantErr: true,
		},
	} {
		d := caddyfile.NewTestDispenser(tc.input)
		var m MatchClientCert
		err := m.UnmarshalCaddyfile(d)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Test %d: expected error but got none", i)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if (m.Verified == nil) != (tc.expect.Verified == nil) ||
			(m.Verified != nil && *m.Verified != *tc.expect.Verified) {
			t.Errorf("Test %d: expected verified %v, got %v", i, tc.expect.Verified, m.Verified)
		}
		if !slices.Equal(m.SubjectCommonName, tc.expect.SubjectCommonName) ||
			!slices.Equal(m.SubjectOrganization, tc.expect.SubjectOrganization) ||
			!slices.Equal(m.SubjectOrganizationalUnit, tc.expect.SubjectOrganizationalUnit) ||
			!slices.Equal(m.IssuerCommonName, tc.expect.IssuerCommonName) ||
			!slices.Equal(m.IssuerOrganization, tc.expect.IssuerOrganization) ||
			!slices.Equal(m.SerialNumber, tc.expect.SerialNumber) ||
			!slices.Equal(m.SANDNSNames, tc.expect.SANDNSNames) ||
			!slices.Equal(m.SANEmailAddresses, tc.expect.SANEmailAddresses) {
			t.Errorf("Test %d: expected %+v, got %+v", i, tc.expect, m)
		}
	}
}

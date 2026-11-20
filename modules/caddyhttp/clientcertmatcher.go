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
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(MatchClientCert{})
}

// MatchClientCert matches requests by fields of the TLS client
// certificate presented on the connection (mutual TLS). It is
// typically used at the edge to route requests based on the
// identity encoded in a verified client certificate.
//
// If the request did not arrive over TLS, it never matches. If
// the matcher is empty, it matches any request that arrived over
// TLS, regardless of whether a client certificate was presented.
//
// All configured fields must match (AND); within a field, any one
// of the configured values may match (OR).
//
// SECURITY: Certificate fields are only trustworthy if the
// certificate was verified during the TLS handshake. Configure
// the TLS client_auth connection policy with a verifying mode
// (verify_if_given or require_and_verify) and a trust pool, and
// set the verified field so that only verified certificates
// match. With verify_if_given, clients that present no certificate
// (or fail verification at the handshake layer) can be routed to
// a fallback route by matching verified:false or by simply not
// matching any certificate route.
type MatchClientCert struct {
	// Verified matches whether the presented client certificate
	// chains to a configured trust pool (i.e. the TLS connection
	// has at least one verified chain). If true, a verified client
	// certificate is required; if false, only requests without a
	// verified client certificate match.
	Verified *bool `json:"verified,omitempty"`

	// SubjectCommonName matches the Common Name (CN) of the client
	// certificate's subject.
	SubjectCommonName []string `json:"subject_common_name,omitempty"`

	// SubjectOrganization matches any of the Organization (O) values
	// of the client certificate's subject.
	SubjectOrganization []string `json:"subject_organization,omitempty"`

	// SubjectOrganizationalUnit matches any of the Organizational
	// Unit (OU) values of the client certificate's subject.
	SubjectOrganizationalUnit []string `json:"subject_organizational_unit,omitempty"`

	// IssuerCommonName matches the Common Name (CN) of the client
	// certificate's issuer.
	IssuerCommonName []string `json:"issuer_common_name,omitempty"`

	// IssuerOrganization matches any of the Organization (O) values
	// of the client certificate's issuer.
	IssuerOrganization []string `json:"issuer_organization,omitempty"`

	// SerialNumber matches the client certificate's serial number,
	// in decimal string form.
	SerialNumber []string `json:"serial_number,omitempty"`

	// SANDNSNames matches any of the DNS name subject alternative
	// names of the client certificate.
	SANDNSNames []string `json:"san_dns_names,omitempty"`

	// SANEmailAddresses matches any of the email address subject
	// alternative names of the client certificate.
	SANEmailAddresses []string `json:"san_email_addresses,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (MatchClientCert) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.client_cert",
		New: func() caddy.Module { return new(MatchClientCert) },
	}
}

// Match returns true if r matches m.
func (m MatchClientCert) Match(r *http.Request) bool {
	if r.TLS == nil {
		return false
	}

	if m.Verified != nil {
		verified := len(r.TLS.VerifiedChains) > 0
		if *m.Verified != verified {
			return false
		}
	}

	if !m.hasFieldMatchers() {
		return true
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	leaf := r.TLS.PeerCertificates[0]

	if len(m.SubjectCommonName) > 0 && !matchAnyString(m.SubjectCommonName, leaf.Subject.CommonName) {
		return false
	}
	if len(m.SubjectOrganization) > 0 && !matchAnyString(m.SubjectOrganization, leaf.Subject.Organization...) {
		return false
	}
	if len(m.SubjectOrganizationalUnit) > 0 && !matchAnyString(m.SubjectOrganizationalUnit, leaf.Subject.OrganizationalUnit...) {
		return false
	}
	if len(m.IssuerCommonName) > 0 && !matchAnyString(m.IssuerCommonName, leaf.Issuer.CommonName) {
		return false
	}
	if len(m.IssuerOrganization) > 0 && !matchAnyString(m.IssuerOrganization, leaf.Issuer.Organization...) {
		return false
	}
	if len(m.SerialNumber) > 0 && !matchAnyString(m.SerialNumber, leaf.SerialNumber.String()) {
		return false
	}
	if len(m.SANDNSNames) > 0 && !matchAnyString(m.SANDNSNames, leaf.DNSNames...) {
		return false
	}
	if len(m.SANEmailAddresses) > 0 && !matchAnyString(m.SANEmailAddresses, leaf.EmailAddresses...) {
		return false
	}
	return true
}

// hasFieldMatchers returns true if any certificate field matcher is configured.
func (m MatchClientCert) hasFieldMatchers() bool {
	return len(m.SubjectCommonName) > 0 ||
		len(m.SubjectOrganization) > 0 ||
		len(m.SubjectOrganizationalUnit) > 0 ||
		len(m.IssuerCommonName) > 0 ||
		len(m.IssuerOrganization) > 0 ||
		len(m.SerialNumber) > 0 ||
		len(m.SANDNSNames) > 0 ||
		len(m.SANEmailAddresses) > 0
}

// matchAnyString returns true if any of the accepted values equals any of the actual values.
func matchAnyString(accepted []string, actual ...string) bool {
	for _, want := range accepted {
		for _, got := range actual {
			if want == got {
				return true
			}
		}
	}
	return false
}

// UnmarshalCaddyfile parses Caddyfile tokens for this matcher. Syntax:
//
//	... client_cert {
//	    verified                      [true|false]
//	    subject_common_name           <values...>
//	    subject_organization          <values...>
//	    subject_organizational_unit   <values...>
//	    issuer_common_name            <values...>
//	    issuer_organization           <values...>
//	    serial_number                 <values...>
//	    san_dns_names                 <values...>
//	    san_email_addresses           <values...>
//	}
//
// The verified subdirective without an argument means verified true.
func (m *MatchClientCert) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// values returns the remaining arguments on the current line,
	// requiring at least one value for the subdirective.
	values := func() ([]string, error) {
		args := d.RemainingArgs()
		if len(args) == 0 {
			return nil, d.ArgErr()
		}
		return args, nil
	}

	// iterate to merge multiple matchers into one
	for d.Next() {
		if d.NextArg() {
			return d.Err("malformed client_cert matcher: arguments are not supported; use a block")
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			var vals []string
			var err error
			switch d.Val() {
			case "verified":
				verified := true
				if d.NextArg() {
					verified, err = strconv.ParseBool(d.Val())
					if err != nil {
						return d.Errf("invalid verified value '%s': expected true or false", d.Val())
					}
				}
				if d.NextArg() {
					return d.ArgErr()
				}
				m.Verified = &verified
				continue
			case "subject_common_name":
				vals, err = values()
				m.SubjectCommonName = append(m.SubjectCommonName, vals...)
			case "subject_organization":
				vals, err = values()
				m.SubjectOrganization = append(m.SubjectOrganization, vals...)
			case "subject_organizational_unit":
				vals, err = values()
				m.SubjectOrganizationalUnit = append(m.SubjectOrganizationalUnit, vals...)
			case "issuer_common_name":
				vals, err = values()
				m.IssuerCommonName = append(m.IssuerCommonName, vals...)
			case "issuer_organization":
				vals, err = values()
				m.IssuerOrganization = append(m.IssuerOrganization, vals...)
			case "serial_number":
				vals, err = values()
				m.SerialNumber = append(m.SerialNumber, vals...)
			case "san_dns_names":
				vals, err = values()
				m.SANDNSNames = append(m.SANDNSNames, vals...)
			case "san_email_addresses":
				vals, err = values()
				m.SANEmailAddresses = append(m.SANEmailAddresses, vals...)
			default:
				return d.Errf("unrecognized client_cert matcher option: %s", d.Val())
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ RequestMatcher        = (*MatchClientCert)(nil)
	_ caddyfile.Unmarshaler = (*MatchClientCert)(nil)
)

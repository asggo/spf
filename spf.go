// Package spf can parse an SPF record and determine if a given IP address is
// allowed to send email based on that record. SPF can handle all of the
// mechanisms defined at http://www.openspf.org/SPF_Record_Syntax. The redirect
// mechanism is ignored.
package spf

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
)

// SPF represents an SPF record for a particular Domain. The SPF record
// holds all of the Allow, Deny, and Neutral mechanisms.
type SPF struct {
	Raw        string
	Domain     string
	Version    string
	Mechanisms []*Mechanism
}

// Test evaluates each mechanism to determine the result for the client.
// Mechanisms are evaluated in order until one of them provides a valid
// result. If no valid results are provided, the default result of "Neutral"
// is returned.
func (s *SPF) Test(ip string) Result {
	for _, m := range s.Mechanisms {
		result, err := m.Evaluate(ip)
		if err == nil {
			return result
		}
	}

	return Neutral
}

// Return an SPF record as a string.
func (s *SPF) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Raw: %s\n", s.Raw))
	buf.WriteString(fmt.Sprintf("Domain: %s\n", s.Domain))
	buf.WriteString(fmt.Sprintf("Version: %s\n", s.Version))

	buf.WriteString("Mechanisms:\n")
	for _, m := range s.Mechanisms {
		buf.WriteString(fmt.Sprintf("\t%s\n", m.String()))
	}

	return buf.String()
}

// SPFString returns a formatted SPF object as a string suitable for use in a
// TXT record.
func (s *SPF) SPFString() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("v=%s", s.Version))
	for _, m := range s.Mechanisms {
		buf.WriteString(fmt.Sprintf(" %s", m.SPFString()))
	}

	return buf.String()
}

// Create a new SPF record for the given domain using the provided string. If
// the provided string is not valid an error is returned.
func NewSPF(domain, record string) (*SPF, error) {
	spf := new(SPF)

	spf.Raw = record
	spf.Domain = domain

	if !strings.HasPrefix(record, "v=spf1") {
		return spf, errors.New(fmt.Sprintf("Invalid SPF string: %s", record))
	}

	for _, f := range strings.Fields(record) {
		switch {
		case strings.HasPrefix(f, "v="):
			spf.Version = f[2:]
		default:
			mechanism := NewMechanism(f, domain)

			if !mechanism.Valid() {
				return spf, errors.New(fmt.Sprintf("Invalid mechanism in SPF string: %s", f))
			}

			if mechanism.Name == "include" {
				if mechanism.Domain == domain {
					return spf, fmt.Errorf("include loop detected")
				}
			}

			spf.Mechanisms = append(spf.Mechanisms, mechanism)
		}
	}

	return spf, nil
}

/*
Exported functions.
*/

// SPFTest determines the clients sending status for the given email addres.
//
// SPFTest will return one of the following results:
// Pass, Fail, SoftFail, Neutral, None, TempError, or PermError
func SPFTest(ip, email string) (Result, error) {
	var domain string
	var spfText string

	// Get domain name from email address.
	if strings.Contains(email, "@") {
		parts := strings.Split(email, "@")
		domain = parts[1]
	} else {
		return None, errors.New("Email address must contain an @ sign.")
	}

	// DNS errors during domain name lookup should result in "TempError".
	records, err := net.LookupTXT(domain)
	if err != nil {
		return TempError, err
	}

	// Find the SPF record among the TXT records for the domain.
	for _, record := range records {
		if strings.HasPrefix(record, "v=spf1") {
			spfText = record
			break
		}
	}

	// No SPF record should result in None.
	if spfText == "" {
		return None, nil
	}

	// Create a new SPF struct
	spf, err := NewSPF(domain, spfText)
	if err != nil {
		return PermError, err
	}

	return spf.Test(ip), nil
}

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

/*
* Mechanism struct and associated methods.
 */

// Return a Mechanism as a string
func (m *Mechanism) String() string {
	var buf bytes.Buffer

	buf.WriteString(m.Name)

	if len(m.Domain) != 0 {
		buf.WriteString(fmt.Sprintf(":%s", m.Domain))
	}

	if len(m.Prefix) != 0 {
		buf.WriteString(fmt.Sprintf("/%s", m.Prefix))
	}

	buf.WriteString(fmt.Sprintf(" - %s", m.Result))

	return buf.String()
}

// ResultTag maps the Result code to a suitable char
func (m *Mechanism) ResultTag() string {
	switch m.Result {
	case "Fail":
		return "-"
	case "SoftFail":
		return "~"
	case "Pass":
		return "+"
	case "Neutral":
		return "?"
	}

	return "+"
}

// SPFString return a string representation of a mechanism, suitable for using
// in a TXT record.
func (m *Mechanism) SPFString() string {
	var buf bytes.Buffer

	tag := m.ResultTag()

	if m.Name != "all" && tag != "+" {
		buf.WriteString(tag)
	} else if m.Name == "all" {
		buf.WriteString(tag)
	}

	buf.WriteString(m.Name)

	if len(m.Domain) != 0 {
		switch {
		case m.Name == "redirect":
			buf.WriteString(fmt.Sprintf("=%s", m.Domain))
		case m.Name == "all":
			// Do nothing
		default:
			buf.WriteString(fmt.Sprintf(":%s", m.Domain))
		}
	}

	if len(m.Prefix) != 0 {
		buf.WriteString(fmt.Sprintf("/%s", m.Prefix))
	}

	return buf.String()
}

// Ensure the mechanism is valid
func (m *Mechanism) Valid() bool {
	var result bool
	var name bool
	var ip bool

	switch m.Result {
	case "Pass", "Fail", "SoftFail", "Neutral":
		result = true
	default:
		result = false
	}

	switch m.Name {
	case "all", "a", "mx", "ip4", "ip6", "exists", "include", "ptr", "redirect":
		name = true
	default:
		name = false
	}

	ip = true
	if m.Name == "ip4" || m.Name == "ip6" {
		valid := net.ParseIP(m.Domain)
		ip = (valid != nil)
	}

	return result && name && ip
}

// Evaluate determines if the given IP address is covered by the mechanism.
// If the IP is covered, the mechanism result is returned and error is nil.
// If the IP is not covered an error is returned. The caller must check for
// the error to determine if the result is valid.
func (m *Mechanism) Evaluate(client string) (string, error) {

	clientIP := net.ParseIP(client)

	switch m.Name {
	case "all":
		return m.Result, nil
	case "exists":
		_, err := net.LookupHost(m.Domain)
		if err == nil {
			return m.Result, nil
		}
	case "include":
		email := "info@" + m.Domain
		return SPFTest(client, email)
	case "a":
		networks := aNetworks(m)
		if ipInNetworks(clientIP, networks) {
			return m.Result, nil
		}
	case "mx":
		networks := mxNetworks(m)
		if ipInNetworks(clientIP, networks) {
			return m.Result, nil
		}
	case "ptr":
		if testPTR(m, client) {
			return m.Result, nil
		}
	case "redirect":
		return "", errors.New("redirect mechanism is not fully supported.")
	default:
		network, err := networkCIDR(m.Domain, m.Prefix)
		if err == nil {
			if network.Contains(clientIP) {
				return m.Result, nil
			}
		}
	}

	return "", errors.New("Client was not covered by the mechanism.")
}

// NewMechanism creates a new Mechanism struct using the given string and
// domain name. When the mechanism does not define the domain, the provided
// domain is used as the default.
func NewMechanism(str, domain string) *Mechanism {
	m := new(Mechanism)

	switch string(str[0]) {
	case "-":
		m.Result = "Fail"
		parseMechanism(str[1:], domain, m)
	case "~":
		m.Result = "SoftFail"
		parseMechanism(str[1:], domain, m)
	case "+":
		m.Result = "Pass"
		parseMechanism(str[1:], domain, m)
	case "?":
		m.Result = "Neutral"
		parseMechanism(str[1:], domain, m)
	default:
		m.Result = "Pass"
		parseMechanism(str, domain, m)
	}

	return m
}

/*
 SPF Struct and associated methods.
*/

// Test evaluates each mechanism to determine the result for the client.
// Mechanisms are evaluated in order until one of them provides a valid
// result. If no valid results are provided, the default result of "Neutral"
// is returned.
func (s *SPF) Test(client string) string {
	for _, m := range s.Mechanisms {
		result, err := m.Evaluate(client)
		if err == nil {
			return result
		}
	}

	return "Neutral"
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
func SPFTest(client, email string) (string, error) {
	var domain string
	var spfText string

	// Get domain name from email address.
	if strings.Contains(email, "@") {
		parts := strings.Split(email, "@")
		domain = parts[1]
	} else {
		return "", errors.New("Email address must contain an @ sign.")
	}

	// DNS errors during domain name lookup should result in "TempError".
	records, err := net.LookupTXT(domain)
	if err != nil {
		return "TempError", err
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
		return "None", nil
	}

	// Create a new SPF struct
	spf, err := NewSPF(domain, spfText)
	if err != nil {
		return "PermError", err
	}

	return spf.Test(client), nil
}

/*
Unexported supporting functions.
*/

func parseMechanism(str, domain string, m *Mechanism) {
	ci := strings.Index(str, ":")
	ei := strings.Index(str, "=")
	pi := strings.Index(str, "/")

	switch {
	case ci != -1 && pi != -1: // name:domain/prefix
		m.Name = str[:ci]
		m.Domain = str[ci+1 : pi]
		m.Prefix = str[pi+1:]
	case ci != -1: // name:domain
		m.Name = str[:ci]
		m.Domain = str[ci+1:]
	case pi != -1: // name/prefix
		m.Name = str[:pi]
		m.Domain = domain
		m.Prefix = str[pi+1:]
	case ci == -1 && pi == -1 && ei != -1: // tag=value
		m.Name = str[:ei]
		m.Domain = str[ei+1:]
	default: // name
		m.Name = str
		m.Domain = domain
	}
}

func networkCIDR(addr, prefix string) (*net.IPNet, error) {
	if prefix == "" {
		ip := net.ParseIP(addr)

		prefix = "32"
		if len(ip) == 8 {
			prefix = "128"
		}
	}

	cidrStr := fmt.Sprintf("%s/%s", addr, prefix)

	_, network, err := net.ParseCIDR(cidrStr)
	return network, err
}

func ipInNetworks(client net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(client) {
			return true
		}
	}

	return false
}

func buildNetworks(ips []string, prefix string) []*net.IPNet {
	var networks []*net.IPNet

	for _, ip := range ips {
		network, err := networkCIDR(ip, prefix)
		if err == nil {
			networks = append(networks, network)
		}
	}

	return networks
}

func aNetworks(m *Mechanism) []*net.IPNet {
	ips, _ := net.LookupHost(m.Domain)

	return buildNetworks(ips, m.Prefix)
}

func mxNetworks(m *Mechanism) []*net.IPNet {
	var networks []*net.IPNet

	mxs, _ := net.LookupMX(m.Domain)

	for _, mx := range mxs {
		ips, _ := net.LookupHost(mx.Host)
		networks = append(networks, buildNetworks(ips, m.Prefix)...)
	}

	return networks
}

func testPTR(m *Mechanism, client string) bool {
	names, err := net.LookupAddr(client)

	if err != nil {
		return false
	}

	for _, name := range names {
		if strings.HasSuffix(name, m.Domain) {
			return true
		}
	}

	return false
}

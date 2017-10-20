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

// Mechanism represents a single mechanism in an SPF record.
type Mechanism struct {
	Name   string
	Domain string
	Prefix string
}

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

	return buf.String()
}

// NewMechanism creates a new Mechanism struct using the given string and
// domain name. When the mechanism does not define the domain, the provided
// domain is used as the default.
func NewMechanism(str, domain string) *Mechanism {
	t := new(Mechanism)
	ci := strings.Index(str, ":")
	pi := strings.Index(str, "/")

	switch {
	case ci != -1 && pi != -1: // name:domain/prefix
		t.Name = str[:ci]
		t.Domain = str[ci+1 : pi]
		t.Prefix = str[pi+1:]
	case ci != -1: // name:domain
		t.Name = str[:ci]
		t.Domain = str[ci+1:]
	case pi != -1: // name/prefix
		t.Name = str[:pi]
		t.Domain = domain
		t.Prefix = str[pi+1:]
	default: // name
		t.Name = str
		t.Domain = domain
	}

	return t
}

// SPF represents an SPF record for a particular Domain. The SPF record
// holds all of the Allow, Deny, and Neutral mechanisms.
type SPF struct {
	Raw     string
	Domain  string
	Version string
	Allow   []*Mechanism
	Deny    []*Mechanism
	Neutral []*Mechanism
}

// Determine if an IP address is allowed to send email.
func (s *SPF) Allowed(client string) (bool, error) {
	allowed := false
	clientIP := net.ParseIP(client)

	for _, m := range s.Allow {
		switch m.Name {
		case "all":
			allowed = true
		case "exists":
			_, err := net.LookupHost(s.Domain)
			allowed = (err == nil)
		case "include":
			spf, err := NewSPFDomain(m.Domain)
			if err == nil {
				allowed, err = spf.Allowed(client)
			}
		case "a":
			networks := aNetworks(m)
			allowed = ipInNetworks(clientIP, networks)
		case "mx":
			networks := mxNetworks(m)
			allowed = ipInNetworks(clientIP, networks)
		case "ptr":
			allowed = testPTR(m, client)
		default:
			network, err := NetworkCIDR(m.Domain, m.Prefix)
			if err == nil {
				allowed = network.Contains(clientIP)
			}
		}

		if allowed {
			return true, nil
		}
	}

	return false, nil
}

// Return an SPF record as a string.
func (s *SPF) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Raw: %s\n", s.Raw))
	buf.WriteString(fmt.Sprintf("Domain: %s\n", s.Domain))
	buf.WriteString(fmt.Sprintf("Version: %s\n", s.Version))

	buf.WriteString("Allow:\n")
	for _, a := range s.Allow {
		buf.WriteString(fmt.Sprintf("\t%s\n", a.String()))
	}

	buf.WriteString("Deny:\n")
	for _, a := range s.Deny {
		buf.WriteString(fmt.Sprintf("\t%s\n", a.String()))
	}

	buf.WriteString("Neutral:\n")
	for _, a := range s.Neutral {
		buf.WriteString(fmt.Sprintf("\t%s\n", a.String()))
	}

	return buf.String()
}

// Create a new SPF record using a domain name. If no SPF record is found for
// the given domain an error is returned.
func NewSPFDomain(domain string) (*SPF, error) {
	spf := new(SPF)

	records, _ := net.LookupTXT(domain)

	for _, record := range records {
		if strings.HasPrefix(record, "v=spf1") {
			return NewSPFString(domain, record)
		}
	}

	return spf, errors.New(fmt.Sprintf("No SPF record for domain: %s", domain))
}


// Create a new SPF record for the given domain using the provided string. If
// the provided string is not valid an error is returned.
func NewSPFString(domain, record string) (*SPF, error) {
	spf := new(SPF)
	spf.Raw = record

	if !strings.HasPrefix(record, "v=spf1") {
		return spf, errors.New(fmt.Sprintf("Invalid SPF string: %s", record))
	}

	spf.Domain = domain

	for _, f := range strings.Fields(record) {
		switch {
		case strings.HasPrefix(f, "v="):
			spf.Version = f[2:]
		case strings.HasPrefix(f, "-"):
			spf.Deny = append(spf.Deny, NewMechanism(f[1:], domain))
		case strings.HasPrefix(f, "~"):
			spf.Neutral = append(spf.Neutral, NewMechanism(f[1:], domain))
		case strings.HasPrefix(f, "+"):
			spf.Allow = append(spf.Allow, NewMechanism(f[1:], domain))
		default:
			spf.Allow = append(spf.Allow, NewMechanism(f, domain))
		}
	}

	return spf, nil
}

// Create a new net.IPNet object using the given IP address and mask.  
func NetworkCIDR(addr, prefix string) (*net.IPNet, error) {
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

func aNetworks(term *Mechanism) []*net.IPNet {
	var networks []*net.IPNet

	ips, _ := net.LookupHost(term.Domain)

	for _, ip := range ips {
		network, err := NetworkCIDR(ip, term.Prefix)
		if err == nil {
			networks = append(networks, network)
		}
	}

	return networks
}

func mxNetworks(term *Mechanism) []*net.IPNet {
	var networks []*net.IPNet

	mxs, _ := net.LookupMX(term.Domain)

	for _, mx := range mxs {
		ips, _ := net.LookupHost(mx.Host)

		for _, ip := range ips {
			network, err := NetworkCIDR(ip, term.Prefix)
			if err == nil {
				networks = append(networks, network)
			}
		}
	}

	return networks
}

func testPTR(term *Mechanism, client string) bool {
	names, err := net.LookupAddr(client)

	if err != nil {
		return false
	}

	for _, name := range names {
		if strings.HasSuffix(name, term.Domain) {
			return true
		}
	}

	return false
}

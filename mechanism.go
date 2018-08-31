package spf

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
)

type Result string

const (
	Pass      Result = "Pass"
	Neutral   Result = "Neutral"
	Fail      Result = "Fail"
	SoftFail  Result = "SoftFail"
	None      Result = "None"
	TempError Result = "TempError"
	PermError Result = "PermError"
)

// Mechanism represents a single mechanism in an SPF record.
type Mechanism struct {
	Name   string
	Domain string
	Prefix string
	Result Result
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

	buf.WriteString(fmt.Sprintf(" - %s", m.Result))

	return buf.String()
}

// ResultTag maps the Result code to a suitable char
func (m *Mechanism) ResultTag() string {
	switch m.Result {
	case Fail:
		return "-"
	case SoftFail:
		return "~"
	case Pass:
		return "+"
	case Neutral:
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

	if len(m.Domain) != 0 && m.Name != "all" {
		buf.WriteString(fmt.Sprintf(":%s", m.Domain))
	}

	if len(m.Prefix) != 0 {
		buf.WriteString(fmt.Sprintf("/%s", m.Prefix))
	}

	return buf.String()
}

// Ensure the mechanism is valid
func (m *Mechanism) Valid() bool {
	var hasResult bool
	var hasName bool
	var isIP bool

	switch m.Result {
	case Pass, Fail, SoftFail, Neutral:
		hasResult = true
	default:
		hasResult = false
	}

	switch m.Name {
	case "all", "a", "mx", "ip4", "ip6", "exists", "include", "ptr":
		hasName = true
	default:
		hasName = false
	}

	isIP = true
	if m.Name == "ip4" || m.Name == "ip6" {
		valid := net.ParseIP(m.Domain)
		isIP = (valid != nil)
	}

	return hasResult && hasName && isIP
}

// Evaluate determines if the given IP address is covered by the mechanism.
// If the IP is covered, the mechanism result is returned and error is nil.
// If the IP is not covered an error is returned. The caller must check for
// the error to determine if the result is valid.
func (m *Mechanism) Evaluate(ip string) (Result, error) {

	parsedIP := net.ParseIP(ip)

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
		return SPFTest(ip, email)
	case "a":
		networks := aNetworks(m)
		if ipInNetworks(parsedIP, networks) {
			return m.Result, nil
		}
	case "mx":
		networks := mxNetworks(m)
		if ipInNetworks(parsedIP, networks) {
			return m.Result, nil
		}
	case "ptr":
		if testPTR(m, ip) {
			return m.Result, nil
		}
	default:
		network, err := networkCIDR(m.Domain, m.Prefix)
		if err == nil {
			if network.Contains(parsedIP) {
				return m.Result, nil
			}
		}
	}

	return None, errors.New("Client was not covered by the mechanism.")
}

// NewMechanism creates a new Mechanism struct using the given string and
// domain name. When the mechanism does not define the domain, the provided
// domain is used as the default.
func NewMechanism(str, domain string) *Mechanism {
	m := new(Mechanism)

	switch string(str[0]) {
	case "-":
		m.Result = Fail
		parseMechanism(str[1:], domain, m)
	case "~":
		m.Result = SoftFail
		parseMechanism(str[1:], domain, m)
	case "+":
		m.Result = Pass
		parseMechanism(str[1:], domain, m)
	case "?":
		m.Result = Neutral
		parseMechanism(str[1:], domain, m)
	default:
		m.Result = Pass
		parseMechanism(str, domain, m)
	}

	return m
}

func parseMechanism(str, domain string, m *Mechanism) {
	ci := strings.Index(str, ":")
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
	default: // name
		m.Name = str
		m.Domain = domain
	}
}

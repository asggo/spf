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

var (
	ErrNoMatch = errors.New("Client was not covered by the mechanism.")
)

// Mechanism represents a single mechanism in an SPF record.
type Mechanism struct {
	Name   string
	Domain string
	Prefix string
	Result Result
	Count  int
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

	switch m.Name {
	case "redirect":
		buf.WriteString(fmt.Sprintf("%s=%s", m.Name, m.Domain))
	case "all":
		buf.WriteString(fmt.Sprintf("%s%s", tag, m.Name))
	default:
		if tag != "+" {
			buf.WriteString(tag)
		}

		buf.WriteString(m.Name)

		if len(m.Domain) != 0 {
			buf.WriteString(fmt.Sprintf(":%s", m.Domain))
		}

		if len(m.Prefix) != 0 {
			buf.WriteString(fmt.Sprintf("/%s", m.Prefix))
		}
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
	case "all", "a", "mx", "ip4", "ip6", "exists", "include", "ptr", "redirect":
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
func (m *Mechanism) Evaluate(ip string, count int) (Result, error) {

	parsedIP := net.ParseIP(ip)

	switch m.Name {
	case "all":
		return m.Result, nil
	case "exists":
		_, err := net.LookupHost(m.Domain)
		if err == nil {
			return m.Result, nil
		}
	case "redirect":
		spf, err := NewSPF(m.Domain, "", count)

		// There is no clear definition of what to do with errors on a
		// redirected domain. Trying to make wise choices here.
		switch err {
		case nil:
			break
		case ErrFailedLookup:
			return TempError, nil
		default:
			return PermError, nil
		}

		return spf.Test(ip), nil
	case "include":
		spf, err := NewSPF(m.Domain, "", count)

		// If there is no SPF record for the included domain or if we have too
		// many mechanisms that require DNS lookups it is considered a
		// PermError. Any other error is ok to ignore.
		if err == ErrNoRecord || err == ErrMaxCount {
			return PermError, nil
		}

		// The include statment is meant to be used as an if-pass or on-pass
		// statement. Meaning if we get a result other than Pass or PermError,
		// it is ok to ignore it and move on to the other mechanisms.
		result := spf.Test(ip)
		if result == Pass || result == PermError {
			return result, nil
		}
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

	return None, ErrNoMatch
}

// NewMechanism creates a new Mechanism struct using the given string and
// domain name. When the mechanism does not define the domain, the provided
// domain is used as the default.
func NewMechanism(str, domain string) (Mechanism, error) {
	var m Mechanism
	var err error

	switch string(str[0]) {
	case "-":
		m, err = parseMechanism(Fail, str[1:], domain)
	case "~":
		m, err = parseMechanism(SoftFail, str[1:], domain)
	case "+":
		m, err = parseMechanism(Pass, str[1:], domain)
	case "?":
		m, err = parseMechanism(Neutral, str[1:], domain)
	default:
		m, err = parseMechanism(Pass, str, domain)
	}

	return m, err
}

func parseMechanism(r Result, str, domain string) (Mechanism, error) {
	var m Mechanism
	var n string
	var d string
	var p string

	ci := strings.Index(str, ":")
	pi := strings.Index(str, "/")
	ei := strings.Index(str, "=")

	switch {
	case ei != -1:
		n = str[:ei]
		d = str[ei+1:]

		// Domain should not be empty
		if d == "" {
			return m, ErrInvalidMechanism
		}
	case ci != -1 && pi != -1 && ci < pi: // name:domain/prefix
		n = str[:ci]
		d = str[ci+1 : pi]
		p = str[pi+1:]

		// Domain and prefix should not be empty
		if d == "" || p == "" {
			return m, ErrInvalidMechanism
		}
	case ci != -1: // name:domain
		n = str[:ci]
		d = str[ci+1:]
		// Domain should not be empty
		if d == "" {
			return m, ErrInvalidMechanism
		}
	case pi != -1: // name/prefix
		n = str[:pi]
		d = domain
		p = str[pi+1:]

		// Prefix should not be empty
		if p == "" {
			return m, ErrInvalidMechanism
		}
	default: // name
		n = str
		d = domain
	}

	m.Result = r
	m.Domain = d
	m.Name = n
	m.Prefix = p

	return m, nil
}

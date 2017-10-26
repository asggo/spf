package spf

import (
	"testing"
)

const domain = "google.com"

type mechtest struct {
	raw    string
	name   string
	domain string
	prefix string
	result string
}

type spferror struct {
	domain string
	raw    string
}

type spftest struct {
	server string
	email  string
	result string
}

func TestNewMechanism(t *testing.T) {
	tests := []mechtest{
		mechtest{"+all", "all", domain, "", "Pass"},
		mechtest{"-ip6:1080::8:800:68.0.3.1", "ip6", "1080::8:800:68.0.3.1", "", "Fail"},
		mechtest{"~ip6:1080::8:800:68.0.3.1/96", "ip6", "1080::8:800:68.0.3.1", "96", "SoftFail"},
		mechtest{"?ip4:192.168.0.1", "ip4", "192.168.0.1", "", "Neutral"},
		mechtest{"ip4:192.168.0.1/16", "ip4", "192.168.0.1", "16", "Pass"},
		mechtest{"-a", "a", domain, "", "Fail"},
		mechtest{"~a/24", "a", domain, "24", "SoftFail"},
		mechtest{"?a:offsite.example.com", "a", "offsite.example.com", "", "Neutral"},
		mechtest{"a:offsite.example.com/24", "a", "offsite.example.com", "24", "Pass"},
		mechtest{"mx", "mx", domain, "", "Pass"},
		mechtest{"mx/24", "mx", domain, "24", "Pass"},
		mechtest{"mx:deferrals.domain.com", "mx", "deferrals.domain.com", "", "Pass"},
		mechtest{"mx:deferrals.domain.com/24", "mx", "deferrals.domain.com", "24", "Pass"},
		mechtest{"ptr", "ptr", domain, "", "Pass"},
		mechtest{"ptr:domain.name", "ptr", "domain.name", "", "Pass"},
		mechtest{"include:domain.name", "include", "domain.name", "", "Pass"},
		mechtest{"exists:domain.name", "exists", "domain.name", "", "Pass"},
	}

	for _, expected := range tests {
		actual := NewMechanism(expected.raw, domain)

		if expected.name != actual.Name {
			t.Error("Expected", expected.name, "got", actual.Name, ":", expected.raw)
		}
		if expected.domain != actual.Domain {
			t.Error("Expected", expected.domain, "got", actual.Domain, ":", expected.raw)
		}
		if expected.prefix != actual.Prefix {
			t.Error("Expected", expected.prefix, "got", actual.Prefix, ":", expected.raw)
		}
		if expected.result != actual.Result {
			t.Error("Expected", expected.prefix, "got", actual.Prefix, ":", expected.raw)
		}
	}
}

func TestNewSPF(t *testing.T) {
	errorTests := []spferror{
		spferror{"google.com", "somestring"},
		spferror{"google.com", "v=spf1 include:_spf.google.com ~all -none"},
	}

	for _, expected := range errorTests {
		_, err := NewSPF(expected.domain, expected.raw)

		if err == nil {
			t.Error("Expected error got nil")
		}
	}
}

func TestSPFTest(t *testing.T) {
	tests := []spftest{
		spftest{"127.0.0.1", "info@google.com", "SoftFail"},
		spftest{"74.125.141.26", "info@google.com", "Pass"},
	}

	for _, expected := range tests {
		actual, err := SPFTest(expected.server, expected.email)
		if err != nil {
			t.Error(err)
		}

		if actual != expected.result {
			t.Error("Expected", expected.result, "got", actual)
		}
	}
}

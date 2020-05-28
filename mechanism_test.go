package spf

import (
	"testing"
)

type mechtest struct {
	raw    string
	name   string
	domain string
	prefix string
	result Result
}

func TestValidMechanism(t *testing.T) {
	tests := []string{
		"ip4:",
 		"include:",
 		"ip4:127.0.0.1/",
 		"ip4:/",
 		"ip4/:",
 	    "/:",
 		":/",
		"redirect=",
		"=",
	}

	for _, expected := range tests {
		_, err := NewMechanism(expected, "domain")
		if err == nil {
			t.Log("Analyzing", expected)
			t.Error("Expecting invalid mechanism")
		}
	}
}

func TestNewMechanism(t *testing.T) {
	tests := []mechtest{
		mechtest{"+all", "all", domain, "", Pass},
		mechtest{"-ip6:1080::8:800:68.0.3.1", "ip6", "1080::8:800:68.0.3.1", "", Fail},
		mechtest{"~ip6:1080::8:800:68.0.3.1/96", "ip6", "1080::8:800:68.0.3.1", "96", SoftFail},
		mechtest{"?ip4:192.168.0.1", "ip4", "192.168.0.1", "", Neutral},
		mechtest{"ip4:192.168.0.1/16", "ip4", "192.168.0.1", "16", Pass},
		mechtest{"-a", "a", domain, "", Fail},
		mechtest{"~a/24", "a", domain, "24", SoftFail},
		mechtest{"?a:offsite.example.com", "a", "offsite.example.com", "", Neutral},
		mechtest{"a:offsite.example.com/24", "a", "offsite.example.com", "24", Pass},
		mechtest{"mx", "mx", domain, "", Pass},
		mechtest{"mx/24", "mx", domain, "24", Pass},
		mechtest{"mx:deferrals.domain.com", "mx", "deferrals.domain.com", "", Pass},
		mechtest{"mx:deferrals.domain.com/24", "mx", "deferrals.domain.com", "24", Pass},
		mechtest{"ptr", "ptr", domain, "", Pass},
		mechtest{"ptr:domain.name", "ptr", "domain.name", "", Pass},
		mechtest{"include:domain.name", "include", "domain.name", "", Pass},
		mechtest{"exists:domain.name", "exists", "domain.name", "", Pass},
		mechtest{"redirect:domain.name", "redirect", "domain.name", "", Pass},
	}

	for _, expected := range tests {
		actual, _ := NewMechanism(expected.raw, domain)

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

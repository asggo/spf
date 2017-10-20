package spf

import (
	"fmt"
	"net"
	"testing"
)

const domain = "google.com"

type mechtest struct {
	raw    string
	name   string
	domain string
	prefix string
}

type spftest struct {
	raw     string
	domain  string
	client  string
	allowed bool
}

type nettest struct {
	ip   string
	mask string
	cidr string
}

func TestNewMechanism(t *testing.T) {
	tests := []mechtest{
		mechtest{"all", "all", domain, ""},
		mechtest{"ip6:1080::8:800:68.0.3.1", "ip6", "1080::8:800:68.0.3.1", ""},
		mechtest{"ip6:1080::8:800:68.0.3.1/96", "ip6", "1080::8:800:68.0.3.1", "96"},
		mechtest{"ip4:192.168.0.1", "ip4", "192.168.0.1", ""},
		mechtest{"ip4:192.168.0.1/16", "ip4", "192.168.0.1", "16"},
		mechtest{"a", "a", domain, ""},
		mechtest{"a/24", "a", domain, "24"},
		mechtest{"a:offsite.example.com", "a", "offsite.example.com", ""},
		mechtest{"a:offsite.example.com/24", "a", "offsite.example.com", "24"},
		mechtest{"mx", "mx", domain, ""},
		mechtest{"mx/24", "mx", domain, "24"},
		mechtest{"mx:deferrals.domain.com", "mx", "deferrals.domain.com", ""},
		mechtest{"mx:deferrals.domain.com/24", "mx", "deferrals.domain.com", "24"},
		mechtest{"ptr", "ptr", domain, ""},
		mechtest{"ptr:domain.name", "ptr", "domain.name", ""},
		mechtest{"include:domain.name", "include", "domain.name", ""},
		mechtest{"exists:domain.name", "exists", "domain.name", ""},
	}

	for _, test := range tests {
		term := NewMechanism(test.raw, domain)

		if test.name != term.Name {
			fmt.Println(test.raw)
			t.Error("Expected", test.name, "got", term.Name)
		}
		if test.domain != term.Domain {
			fmt.Println(test.raw)
			t.Error("Expected", test.domain, "got", term.Domain)
		}
		if test.prefix != term.Prefix {
			fmt.Println(test.raw)
			t.Error("Expected", test.prefix, "got", term.Prefix)
		}
	}
}

func TestNewSPFString(t *testing.T) {
	tests := []spftest{
		spftest{"v=spf1 include:_spf.google.com ~all", "google.com", "172.217.0.0", true},
		spftest{"v=spf1 include:_spf.google.com ~all", "google.com", "127.217.0.0", false},
		spftest{"v=spf1 ip4:148.163.158.5 mx ~all", "ibm.com", "148.163.156.1", true},
		spftest{"v=spf1 ip4:148.163.158.5 mx ~all", "ibm.com", "148.163.156.2", false},
	}

	_, err := NewSPFString("domain", "somestring")
	if err == nil {
		t.Error("Invalid SPF string should throw an error.")
	}

	for _, test := range tests {
		spf, err := NewSPFString(test.domain, test.raw)

		if err != nil {
			t.Error("Unexpected error with test:", test.raw, err)
		}

		allowed, err := spf.Allowed(test.client)
		if allowed != test.allowed {
			fmt.Println(test.client)
			t.Error("Expected", test.allowed, "got", allowed, err)
		}

	}
}

func TestNewSPFDomain(t *testing.T) {
	_, err := NewSPFDomain("www.apple.com")
	if err == nil {
		t.Error("Should receive a no SPF record error.")
	}

	_, err = NewSPFDomain("google.com")
	if err != nil {
		t.Error("Expected new SPF Record for google.com, received error.")
	}
}

func TestNetworkCIDR(t *testing.T) {
	tests := []nettest{
		nettest{"192.168.0.0", "24", "192.168.0.0/24"},
		nettest{"1080::8:800:68.0.3.1", "128", "1080::8:800:68.0.3.1/128"},
	}

	_, err := NetworkCIDR("192.168.0.0", "34")
	if err == nil {
		t.Error("Expected error got nil.")
	}

	for _, test := range tests {
		actual, err := NetworkCIDR(test.ip, test.mask)
		if err != nil {
			t.Error("Unexpected error creating network:", err)
		}

		_, expected, _ := net.ParseCIDR(test.cidr)

		if actual.String() != expected.String() {
			t.Error("Expected", expected.String(), "got", actual.String())
		}
	}
}

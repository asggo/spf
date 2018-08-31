package spf

import (
	"fmt"
	"net"
	"strings"
)

func networkCIDR(addr, prefix string) (*net.IPNet, error) {
	if prefix == "" {
		ip := net.ParseIP(addr)

		if ip.To4() != nil {
			prefix = "32"
		} else {
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

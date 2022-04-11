package gateway

// Adapted from:
// https://github.com/berty/berty/blob/7ff787f6dbff39f38c73d11393da593e615accdf/go/framework/bertybridge/driver_net.go#L36-L66

import (
	"net"
	"strings"
)

type inet struct {
	addrs []net.Addr
}

func (ia *inet) InterfaceAddrs() ([]net.Addr, error) {
	return ia.addrs, nil
}

func parseInterfaceString(ifaceString string) []net.Addr {
	addrs := []net.Addr{}
	for _, addr := range strings.Split(ifaceString, "\n") {
		// String format is IP address, possibly with interface:
		// fe80::2f60:2c82:4163:8389%wlan0

		if addr == "" {
			continue
		}

		// skip interface name
		ips := strings.Split(addr, "%")
		if len(ips) == 0 {
			continue
		}
		ip := ips[0]

		// resolve ip
		v, err := net.ResolveIPAddr("ip", ip)
		if err != nil {
			continue
		}

		addrs = append(addrs, v)
	}
	return addrs
}

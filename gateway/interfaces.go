package gateway

// Adapted from:
// https://github.com/berty/berty/blob/7ff787f6dbff39f38c73d11393da593e615accdf/go/framework/bertybridge/driver_net.go#L36-L66

import (
	"fmt"
	"log"
	"net"
	"strings"
)

type inet struct {
	addrs []net.Addr
}

func (ia *inet) InterfaceAddrs() ([]net.Addr, error) {
	return ia.addrs, nil
}

var androidAddrs = make([]net.Addr, 0)
var androidInterfaces = make([]net.Interface, 0)

func parseInterfacesString(interfaces string) {
	// Adapted from:
	// https://github.com/tailscale/tailscale-android/blob/e652d853d6aa574c9a3f277695cd286c2b32a088/cmd/tailscale/main.go#L1316-L1382

	for _, iface := range strings.Split(interfaces, "\n") {
		// Example of the strings we're processing:
		// wlan0 30 1500 true true false false true | fe80::2f60:2c82:4163:8389%wlan0/64 10.1.10.131/24
		// r_rmnet_data0 21 1500 true false false false false | fe80::9318:6093:d1ad:ba7f%r_rmnet_data0/64
		// mnet_data2 12 1500 true false false false false | fe80::3c8c:44dc:46a9:9907%rmnet_data2/64

		if strings.TrimSpace(iface) == "" {
			continue
		}

		fields := strings.Split(iface, "|")
		if len(fields) != 2 {
			log.Printf("parseInterfacesString: unable to split %q", iface)
			continue
		}

		var name string
		var index, mtu int
		var up, broadcast, loopback, pointToPoint, multicast bool
		_, err := fmt.Sscanf(fields[0], "%s %d %d %t %t %t %t %t",
			&name, &index, &mtu, &up, &broadcast, &loopback, &pointToPoint, &multicast)
		if err != nil {
			log.Printf("parseInterfacesString: unable to parse %q: %v", iface, err)
			continue
		}

		newIf := net.Interface{
			Name:  name,
			Index: index,
			MTU:   mtu,
		}
		if up {
			newIf.Flags |= net.FlagUp
		}
		if broadcast {
			newIf.Flags |= net.FlagBroadcast
		}
		if loopback {
			newIf.Flags |= net.FlagLoopback
		}
		if pointToPoint {
			newIf.Flags |= net.FlagPointToPoint
		}
		if multicast {
			newIf.Flags |= net.FlagMulticast
		}

		addrs := strings.Trim(fields[1], " \n")
		for _, addr := range strings.Split(addrs, " ") {
			_, ipnet, err := net.ParseCIDR(addr)
			if err == nil {
				androidAddrs = append(androidAddrs, ipnet)
			}
		}

		androidInterfaces = append(androidInterfaces, newIf)
	}
}

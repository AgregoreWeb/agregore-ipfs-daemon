package gateway

import (
	"context"
	"log"
	"net"

	"github.com/AgregoreWeb/agregore-ipfs-daemon/mdns"
	"github.com/libp2p/go-libp2p-core/host"
)

func startMdnsService(ifaces []net.Interface, host host.Host) error {
	// Adapted from:
	// https://github.com/berty/berty/blob/e053901de13a6bc3a26952a57d7382fd6792a545/go/internal/initutil/ipfs.go#L223-L247

	dh := mdns.DiscoveryHandler(context.Background(), nil, host)
	mdnsService := mdns.NewMdnsService(nil, host, mdns.MDNSServiceName, dh, ifaces)

	multicastIfaces := mdns.GetMulticastInterfaces(mdnsService.(*mdns.MdnsService))

	// if multicast interfaces is found, start mdns service
	if len(multicastIfaces) > 0 {
		log.Println("starting mdns")
		if err := mdnsService.Start(); err != nil {
			log.Printf("error starting mdns: %v", err)
			return err
		}
	} else {
		log.Println("unable to start mdns service, no multicast interfaces found")
	}

	return nil
}

package waterutil

import "net"

func IPVersion(packet []byte) byte {
	return packet[0] >> 4
}

func IPSource(packet []byte) net.IP {
	switch IPVersion(packet) {
	case 4:
		return IPv4Source(packet)
	case 6:
		return IPv6Source(packet)
	default:
		return nil
	}
}

func IPDestination(packet []byte) net.IP {
	switch IPVersion(packet) {
	case 4:
		return IPv4Destination(packet)
	case 6:
		return IPv6Destination(packet)
	default:
		return nil
	}
}

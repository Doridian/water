package waterutil

import "net"

func IPv6Source(packet []byte) net.IP {
	return net.IP(packet[8:24])
}

func SetIPv6Source(packet []byte, source net.IP) {
	copy(packet[12:16], source.To4())
}

func IPv6Destination(packet []byte) net.IP {
	return net.IP(packet[24:40])
}

func SetIPv6Destination(packet []byte, dest net.IP) {
	copy(packet[16:20], dest.To4())
}

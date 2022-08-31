package waterutil

import "net"

func IPv6Source(packet []byte) net.IP {
	return net.IP(packet[8:24])
}

func SetIPv6Source(packet []byte, source net.IP) {
	copy(packet[8:24], source.To16())
}

func IPv6Destination(packet []byte) net.IP {
	return net.IP(packet[24:40])
}

func SetIPv6Destination(packet []byte, dest net.IP) {
	copy(packet[24:40], dest.To16())
}

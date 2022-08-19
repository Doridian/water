package water

import (
	"net"
	"os/exec"
	"testing"
)

func startPing(t *testing.T, dst net.IP) {
	params := []string{"-c", "4", dst.String()}
	if err := exec.Command("ping", params...).Start(); err != nil {
		t.Fatal(err)
	}
}

func setupIfce(t *testing.T, self net.IP, remote net.IP, dev string) {
	if err := exec.Command("ifconfig", dev, "inet", self.String(), remote.String(), "up").Run(); err != nil {
		t.Fatal(err)
	}
}

func setupIfceTAP(t *testing.T, self net.IPNet, dev string) {
	if err := exec.Command("ifconfig", dev, "inet", self.String(), "up").Run(); err != nil {
		t.Fatal(err)
	}
}

func teardownIfce(t *testing.T, ifce *Interface) {
	if err := ifce.Close(); err != nil {
		t.Fatal(err)
	}
	if ifce.IsTUN() {
		if err := exec.Command("ifconfig", ifce.Name(), "down").Run(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestP2PTUN(t *testing.T) {
	var (
		self   = net.IPv4(10, 0, 42, 1)
		remote = net.IPv4(10, 0, 42, 2)
	)

	ifce, err := New(Config{DeviceType: TUN})
	if err != nil {
		t.Fatalf("creating TUN error: %v\n", err)
	}
	defer teardownIfce(t, ifce)

	dataCh, errCh := startRead(t, ifce)

	setupIfce(t, self, remote, ifce.Name())
	startPing(t, remote)

	waitForPingOrBust(t, false, false, self, remote, dataCh, errCh)
}

func TestBroadcastTAP(t *testing.T) {
	var (
		self = net.IPv4(10, 0, 42, 1)
		mask = net.IPv4Mask(255, 255, 255, 0)
		brd  = net.IPv4(10, 0, 42, 255)
	)

	ifce, err := New(Config{DeviceType: TAP})
	if err != nil {
		t.Fatalf("creating TAP error: %v\n", err)
	}
	defer teardownIfce(t, ifce)

	dataCh, errCh := startRead(t, ifce)

	setupIfceTAP(t, net.IPNet{IP: self, Mask: mask}, ifce.Name())
	startPing(t, brd)

	waitForPingOrBust(t, true, true, self, brd, dataCh, errCh)
}

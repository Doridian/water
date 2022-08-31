package water

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Doridian/water/waterutil"
)

const BUFFERSIZE = 1522

func startRead(t *testing.T, ifce *Interface) (dataChan <-chan []byte, errChan <-chan error) {
	dataCh := make(chan []byte)
	errCh := make(chan error)
	go func() {
		for {
			buffer := make([]byte, BUFFERSIZE)
			n, err := ifce.Read(buffer)
			if err != nil {
				errCh <- err
			} else {
				buffer = buffer[:n:n]
				dataCh <- buffer
			}
		}
	}()
	return dataCh, errCh
}

func waitForPingOrBust(t *testing.T,
	isTAP bool,
	expectBroadcast bool,
	expectSrc net.IP,
	expectDest net.IP,
	dataCh <-chan []byte, errCh <-chan error) {
	waitForPintTimeout := time.NewTimer(8 * time.Second).C
readFrame:
	for {
		select {
		case buffer := <-dataCh:
			var packet []byte
			if isTAP {
				ethertype := waterutil.MACEthertype(buffer)
				if ethertype != waterutil.IPv4 {
					continue readFrame
				}
				if expectBroadcast && !waterutil.IsMACBroadcast(waterutil.MACDestination(buffer)) {
					continue readFrame
				}
				packet = waterutil.MACPayload(buffer)
			} else {
				packet = buffer
			}
			if waterutil.IPVersion(packet) != 4 {
				continue readFrame
			}
			if !waterutil.IPv4Source(packet).Equal(expectSrc) {
				continue readFrame
			}
			if !waterutil.IPv4Destination(packet).Equal(expectDest) {
				continue readFrame
			}
			if waterutil.IPv4Protocol(packet) != waterutil.ICMP {
				continue readFrame
			}
			t.Logf("received broadcast frame: %#v\n", buffer)
			break readFrame
		case err := <-errCh:
			t.Fatalf("read error: %v", err)
		case <-waitForPintTimeout:
			t.Fatal("Waiting for broadcast packet timeout")
		}
	}
}

func TestCloseUnblockPendingRead(t *testing.T) {
	ifce, err := New(Config{DeviceType: TUN})
	if err != nil {
		t.Fatalf("creating TUN error: %v\n", err)
	}

	c := make(chan struct{})
	go func() {
		ifce.Read(make([]byte, 1<<16))
		close(c)
	}()

	// make sure ifce.Close() happens after ifce.Read() blocks
	time.Sleep(1 * time.Second)

	ifce.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	select {
	case <-c:
		t.Log("Pending Read unblocked")
	case <-ctx.Done():
		t.Fatal("Timeouted, pending read blocked")
	}
}

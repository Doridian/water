package water

import (
	"errors"
	"fmt"
	"io"
)

type VectorReadWrite interface {
	ReadVector(bufs [][]byte, sizes []int) (n int, err error)
	WriteVector(bufs [][]byte) (n int, err error)
	IsVectorNative() bool
}

// Interface is a TUN/TAP interface.
//
// MultiQueue(Linux kernel > 3.8): With MultiQueue enabled, user should hold multiple
// interfaces to send/receive packet in parallel.
// Kernel document about MultiQueue: https://www.kernel.org/doc/Documentation/networking/tuntap.txt
type Interface struct {
	isTAP bool
	VectorReadWrite
	io.ReadWriteCloser
	name          string
	secondaryName string //lint:ignore U1000 This is unused on some operating systems
}

// DeviceType is the type for specifying device types.
type DeviceType int

// TUN and TAP device types.
const (
	_ = iota
	TUN
	TAP
)

// Config defines parameters required to create a TUN/TAP interface. It's only
// used when the device is initialized. A zero-value Config is a valid
// configuration.
type Config struct {
	// DeviceType specifies whether the device is a TUN or TAP interface. A
	// zero-value is treated as TUN.
	DeviceType DeviceType

	// PlatformSpecificParams defines parameters that differ on different
	// platforms. See comments for the type for more details.
	PlatformSpecificParams
}

func defaultConfig() Config {
	return Config{
		DeviceType:             TUN,
		PlatformSpecificParams: defaultPlatformSpecificParams(),
	}
}

var zeroConfig Config

// New creates a new TUN/TAP interface using config.
func New(config Config) (ifce *Interface, err error) {
	if zeroConfig == config {
		config = defaultConfig()
	}
	if config.PlatformSpecificParams == zeroConfig.PlatformSpecificParams {
		config.PlatformSpecificParams = defaultPlatformSpecificParams()
	}
	switch config.DeviceType {
	case TUN, TAP:
		dev, err := openDev(config)
		if err != nil {
			return nil, err
		}
		if dev.VectorReadWrite == nil {
			dev.VectorReadWrite = &ReadWriteVectorProxy{ReadWriteCloser: dev.ReadWriteCloser}
		}
		return dev, nil
	default:
		return nil, errors.New("unknown device type")
	}
}

// IsTUN returns true if ifce is a TUN interface.
func (ifce *Interface) IsTUN() bool {
	return !ifce.isTAP
}

// IsTAP returns true if ifce is a TAP interface.
func (ifce *Interface) IsTAP() bool {
	return ifce.isTAP
}

// Name returns the interface name of ifce, e.g. tun0, tap1, tun0, etc..
func (ifce *Interface) Name() string {
	return ifce.name
}

type ReadWriteVectorProxy struct {
	io.ReadWriteCloser
}

func (p *ReadWriteVectorProxy) ReadVector(bufs [][]byte, sizes []int) (n int, err error) {
	for i, buf := range bufs {
		sizes[i], err = p.ReadWriteCloser.Read(buf)
		if err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (p *ReadWriteVectorProxy) WriteVector(bufs [][]byte) (n int, err error) {
	for i, buf := range bufs {
		n, err = p.ReadWriteCloser.Write(buf)
		if err != nil {
			return i, err
		}
		if n != len(buf) {
			return i, fmt.Errorf("expected to write %d but wrote %d", len(buf), n)
		}
	}
	return len(bufs), nil
}

func (p *ReadWriteVectorProxy) IsVectorNative() bool {
	return false
}

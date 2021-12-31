package water

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/fumiama/wintun"
)

// To use it with windows, you need a tap driver installed on windows.
// https://github.com/OpenVPN/tap-windows6
// or just install OpenVPN
// https://github.com/OpenVPN/openvpn

const (
	// tapDriverKey is the location of the TAP driver key.
	tapDriverKey = `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`
	// netConfigKey is the location of the TAP adapter's network config.
	netConfigKey = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`
)

var (
	errIfceNameNotFound = errors.New("failed to find the name of interface")
	// Device Control Codes
	tap_win_ioctl_get_mac = tap_control_code(1, 0)
	// tap_win_ioctl_get_version         = tap_control_code(2, 0)
	// tap_win_ioctl_get_mtu             = tap_control_code(3, 0)
	// tap_win_ioctl_get_info            = tap_control_code(4, 0)
	// tap_ioctl_config_point_to_point   = tap_control_code(5, 0)
	tap_ioctl_set_media_status = tap_control_code(6, 0)
	// tap_win_ioctl_config_dhcp_masq    = tap_control_code(7, 0)
	// tap_win_ioctl_get_log_line        = tap_control_code(8, 0)
	// tap_win_ioctl_config_dhcp_set_opt = tap_control_code(9, 0)
	// tap_ioctl_config_tun              = tap_control_code(10, 0)
	// w32 api
	file_device_unknown = uint32(0x00000022)
	nCreateEvent,
	nResetEvent,
	nGetOverlappedResult uintptr
)

func init() {
	k32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		panic("LoadLibrary " + err.Error())
	}
	defer syscall.FreeLibrary(k32)

	nCreateEvent = getProcAddr(k32, "CreateEventW")
	nResetEvent = getProcAddr(k32, "ResetEvent")
	nGetOverlappedResult = getProcAddr(k32, "GetOverlappedResult")
}

func getProcAddr(lib syscall.Handle, name string) uintptr {
	addr, err := syscall.GetProcAddress(lib, name)
	if err != nil {
		panic(name + " " + err.Error())
	}
	return addr
}

func resetEvent(h syscall.Handle) error {
	r, _, err := syscall.Syscall(nResetEvent, 1, uintptr(h), 0, 0)
	if r == 0 {
		return err
	}
	return nil
}

func getOverlappedResult(h syscall.Handle, overlapped *syscall.Overlapped) (int, error) {
	var n int
	r, _, err := syscall.Syscall6(nGetOverlappedResult, 4,
		uintptr(h),
		uintptr(unsafe.Pointer(overlapped)),
		uintptr(unsafe.Pointer(&n)), 1, 0, 0)
	if r == 0 {
		return n, err
	}

	return n, nil
}

func newOverlapped() (*syscall.Overlapped, error) {
	var overlapped syscall.Overlapped
	r, _, err := syscall.Syscall6(nCreateEvent, 4, 0, 1, 0, 0, 0, 0)
	if r == 0 {
		return nil, err
	}
	overlapped.HEvent = syscall.Handle(r)
	return &overlapped, nil
}

type wfile struct {
	fd syscall.Handle
	rl sync.Mutex
	wl sync.Mutex
	ro *syscall.Overlapped
	wo *syscall.Overlapped
}

func (f *wfile) Close() error {
	return syscall.Close(f.fd)
}

func (f *wfile) Write(b []byte) (int, error) {
	f.wl.Lock()
	defer f.wl.Unlock()

	if err := resetEvent(f.wo.HEvent); err != nil {
		return 0, err
	}
	var n uint32
	err := syscall.WriteFile(f.fd, b, &n, f.wo)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		return int(n), err
	}
	return getOverlappedResult(f.fd, f.wo)
}

func (f *wfile) Read(b []byte) (int, error) {
	f.rl.Lock()
	defer f.rl.Unlock()

	if err := resetEvent(f.ro.HEvent); err != nil {
		return 0, err
	}
	var done uint32
	err := syscall.ReadFile(f.fd, b, &done, f.ro)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		return int(done), err
	}
	return getOverlappedResult(f.fd, f.ro)
}

func ctl_code(device_type, function, method, access uint32) uint32 {
	return (device_type << 16) | (access << 14) | (function << 2) | method
}

func tap_control_code(request, method uint32) uint32 {
	return ctl_code(file_device_unknown, request, method, 0)
}

// getdeviceid finds out a TAP device from registry, it *may* requires privileged right to prevent some weird issue.
func getdeviceid(componentID string, interfaceName string) (deviceid string, err error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, tapDriverKey, registry.READ)
	if err != nil {
		return "", errors.New("Failed to open the adapter registry, TAP driver may be not installed" + err.Error())
	}
	defer k.Close()
	// read all subkeys, it should not return an err here
	keys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}
	// find the one matched ComponentId
	for _, v := range keys {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, tapDriverKey+"\\"+v, registry.READ)
		if err != nil {
			continue
		}
		val, _, err := key.GetStringValue("ComponentId")
		if err != nil {
			key.Close()
			continue
		}
		if val == componentID {
			val, _, err = key.GetStringValue("NetCfgInstanceId")
			if err != nil {
				key.Close()
				continue
			}
			if len(interfaceName) > 0 {
				key2 := fmt.Sprintf("%s\\%s\\Connection", netConfigKey, val)
				k2, err := registry.OpenKey(registry.LOCAL_MACHINE, key2, registry.READ)
				if err != nil {
					continue
				}
				defer k2.Close()
				val, _, err := k2.GetStringValue("Name")
				if err != nil || val != interfaceName {
					continue
				}
			}
			key.Close()
			return val, nil
		}
		key.Close()
	}
	if len(interfaceName) > 0 {
		return "", errors.New("Failed to find the tap device in registry with specified ComponentId '" + componentID + "' and InterfaceName '" + interfaceName + "', TAP driver may be not installed or you may have specified an interface name that doesn't exist")
	}

	return "", errors.New("Failed to find the tap device in registry with specified ComponentId '" + componentID + "', TAP driver may be not installed")
}

// setStatus is used to bring up or bring down the interface
func setStatus(fd syscall.Handle, status bool) error {
	var bytesReturned uint32
	rdbbuf := make([]byte, syscall.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	code := []byte{0x00, 0x00, 0x00, 0x00}
	if status {
		code[0] = 0x01
	}
	return syscall.DeviceIoControl(fd, tap_ioctl_set_media_status, &code[0], uint32(4), &rdbbuf[0], uint32(len(rdbbuf)), &bytesReturned, nil)
}

func openTap(config Config) (ifce *Interface, err error) {
	if config.ComponentID == "" {
		config.ComponentID = "root\\tap0901"
	}
	// find the device in registry.
	deviceid, err := getdeviceid(config.PlatformSpecificParams.ComponentID, config.PlatformSpecificParams.InterfaceName)
	if err != nil {
		return nil, err
	}
	path := "\\\\.\\Global\\" + deviceid + ".tap"
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// type Handle uintptr
	file, err := syscall.CreateFile(pathp, syscall.GENERIC_READ|syscall.GENERIC_WRITE, uint32(syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE), nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_SYSTEM|syscall.FILE_FLAG_OVERLAPPED, 0)
	// if err hanppens, close the interface.
	defer func() {
		if err != nil {
			syscall.Close(file)
		}
		if err := recover(); err != nil {
			syscall.Close(file)
		}
	}()
	if err != nil {
		return nil, err
	}
	var bytesReturned uint32

	// find the mac address of tap device, use this to find the name of interface
	mac := make([]byte, 6)
	err = syscall.DeviceIoControl(file, tap_win_ioctl_get_mac, &mac[0], uint32(len(mac)), &mac[0], uint32(len(mac)), &bytesReturned, nil)
	if err != nil {
		return nil, err
	}

	// fd := os.NewFile(uintptr(file), path)
	ro, err := newOverlapped()
	if err != nil {
		return
	}
	wo, err := newOverlapped()
	if err != nil {
		return
	}
	fd := &wfile{fd: file, ro: ro, wo: wo}
	ifce = &Interface{isTAP: (config.DeviceType == TAP), ReadWriteCloser: fd}

	// bring up device.
	if err := setStatus(file, true); err != nil {
		return nil, err
	}

	// find the name of tap interface(u need it to set the ip or other command)
	ifces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, v := range ifces {
		if len(v.HardwareAddr) < 6 {
			continue
		}
		if bytes.Equal(v.HardwareAddr[:6], mac[:6]) {
			ifce.name = v.Name
			return
		}
	}

	return nil, errIfceNameNotFound
}

type wintunRWC struct {
	ad       wintun.Adapter
	s        wintun.Session
	readwait windows.Handle
	readbuf  []byte
	isclosed bool
}

func (w *wintunRWC) Close() error {
	w.isclosed = true
	w.s.End()
	return w.ad.Close()
}

func (w *wintunRWC) Write(b []byte) (int, error) {
	packet, err := w.s.AllocateSendPacket(len(b))
	switch err {
	case nil:
		copy(packet, b)
		w.s.SendPacket(packet)
		return len(b), nil
	case windows.ERROR_HANDLE_EOF:
		return 0, os.ErrClosed
	case windows.ERROR_BUFFER_OVERFLOW:
		return 0, nil // Dropping when ring is full.
	default:
		return 0, err
	}
}

func (w *wintunRWC) Read(b []byte) (int, error) {
	n := 0

	if w.readbuf != nil {
		n = copy(b, w.readbuf)
		if len(w.readbuf) >= len(b) {
			w.readbuf = w.readbuf[len(b):]
			if len(w.readbuf) == 0 {
				w.readbuf = nil
			}
			return n, nil
		}
		b = b[len(w.readbuf):]
		w.readbuf = nil
	}

RETRY:
	if w.isclosed {
		return 0, errors.New("wintun is closed")
	}
	packet, err := w.s.ReceivePacket()
	switch err {
	case nil:
		n += copy(b, packet)
		if len(packet) > len(b) {
			w.readbuf = make([]byte, len(packet)-len(b))
			copy(w.readbuf, packet[len(b):])
		}
		w.s.ReleaseReceivePacket(packet)
	case windows.ERROR_NO_MORE_ITEMS:
		windows.WaitForSingleObject(w.readwait, windows.INFINITE)
		goto RETRY
	}
	return n, err
}

// openDev find and open an interface.
func openDev(config Config) (ifce *Interface, err error) {
	// TAP
	if config.DeviceType == TAP {
		return openTap(config)
	}
	// TUN
	var ad *wintun.Adapter
	if config.InterfaceName == "" {
		config.InterfaceName = "WaterWinTunInterface"
	}
	if config.ComponentID == "" {
		config.ComponentID = "WaterWintun"
	}
	ad, err = wintun.OpenAdapter(config.InterfaceName)
	if err != nil {
		ad, err = wintun.CreateAdapter(config.InterfaceName, config.ComponentID, nil)
	}

	if err != nil {
		return
	}
	s, err := ad.StartSession(0x800000) // Ring capacity, 8 MiB
	if err != nil {
		ad.Close()
		return
	}
	return &Interface{ReadWriteCloser: &wintunRWC{s: s, ad: *ad, readwait: s.ReadWaitEvent()}, name: config.InterfaceName}, nil
}

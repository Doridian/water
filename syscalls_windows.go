package water

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"

	wintun "golang.zx2c4.com/wireguard/tun"
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
	defer func() {
		_ = syscall.FreeLibrary(k32)
	}()

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
	r, _, err := syscall.SyscallN(nResetEvent, uintptr(h))
	if r == 0 {
		return err
	}
	return nil
}

func getOverlappedResult(h syscall.Handle, overlapped *syscall.Overlapped) (int, error) {
	var n int
	r, _, err := syscall.SyscallN(nGetOverlappedResult,
		uintptr(h),
		uintptr(unsafe.Pointer(overlapped)),
		uintptr(unsafe.Pointer(&n)), 1)
	if r == 0 {
		return n, err
	}

	return n, nil
}

func newOverlapped() (*syscall.Overlapped, error) {
	var overlapped syscall.Overlapped
	r, _, err := syscall.SyscallN(nCreateEvent, 0, 1, 0, 0)
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
	defer func() {
		_ = k.Close()
	}()
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
			_ = key.Close()
			continue
		}
		if val == componentID {
			val, _, err = key.GetStringValue("NetCfgInstanceId")
			if err != nil {
				_ = key.Close()
				continue
			}
			if len(interfaceName) > 0 {
				key2 := fmt.Sprintf("%s\\%s\\Connection", netConfigKey, val)
				k2, err := registry.OpenKey(registry.LOCAL_MACHINE, key2, registry.READ)
				if err != nil {
					continue
				}
				defer func() {
					_ = k2.Close()
				}()
				val, _, err := k2.GetStringValue("Name")
				if err != nil || val != interfaceName {
					continue
				}
			}
			_ = key.Close()
			return val, nil
		}
		_ = key.Close()
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
	deviceid, err := getdeviceid(config.ComponentID, config.InterfaceName)
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
		if recover() != nil || err != nil {
			_ = syscall.Close(file)
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
	ad  wintun.Device
	rmu sync.Mutex
	wmu sync.Mutex
}

func (w *wintunRWC) Close() error {
	return w.ad.Close()
}

func (w *wintunRWC) ReadVector(bufs [][]byte, sizes []int) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()

	return w.ad.Read(bufs, sizes, 0)
}

func (w *wintunRWC) WriteVector(bufs [][]byte) (int, error) {
	w.wmu.Lock()
	defer w.wmu.Unlock()

	return w.ad.Write(bufs, 0)
}

func (w *wintunRWC) Read(b []byte) (int, error) {
	lens := []int{0}
	res, err := w.ad.Read([][]byte{b}, lens, 0)
	if err != nil {
		return 0, err
	}

	if res <= 0 {
		return res, nil
	}
	return lens[0], nil
}

func (w *wintunRWC) Write(b []byte) (int, error) {
	res, err := w.WriteVector([][]byte{b})
	if err != nil {
		return 0, err
	}

	if res <= 0 {
		return res, nil
	}
	return len(b), nil
}

func (w *wintunRWC) IsVectorNative() bool {
	return true
}

// openDev find and open an interface.
func openDev(config Config) (ifce *Interface, err error) {
	// TAP
	if config.DeviceType == TAP {
		return openTap(config)
	}
	// TUN
	var ad wintun.Device
	if config.InterfaceName == "" {
		config.InterfaceName = "WaterWinTunInterface"
	}
	if config.ComponentID == "" {
		config.ComponentID = "WaterWintun"
	}
	ad, err = wintun.CreateTUN(config.InterfaceName, 1500)

	if err != nil {
		return
	}

	var name string
	name, err = ad.Name()
	if err != nil {
		return
	}

	wt := &wintunRWC{ad: ad}
	return &Interface{VectorReadWrite: wt, ReadWriteCloser: wt, name: name}, nil
}

func (ifce *Interface) SetMTU(mtu int) error {
	err := exec.Command("netsh", "interface", "ipv4", "set", "subinterface", ifce.name, fmt.Sprintf("mtu=%d", mtu)).Run()
	if err != nil {
		return err
	}

	wtun, ok := ifce.ReadWriteCloser.(*wintunRWC)
	if !ok {
		return nil // TAP interface
	}

	ad, ok := wtun.ad.(*wintun.NativeTun)
	if !ok {
		return errors.New("cannot cast ad to NativeTun")
	}
	ad.ForceMTU(mtu)

	return nil
}

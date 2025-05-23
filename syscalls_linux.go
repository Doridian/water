package water

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	cIFFTUN        = 0x0001
	cIFFTAP        = 0x0002
	cIFFNOPI       = 0x1000
	cIFFMULTIQUEUE = 0x0100
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

func ioctl(fd uintptr, request uintptr, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

func setupFd(config Config, fd uintptr) (name string, err error) {
	var flags uint16 = cIFFNOPI
	if config.DeviceType == TUN {
		flags |= cIFFTUN
	} else {
		flags |= cIFFTAP
	}
	if config.MultiQueue {
		flags |= cIFFMULTIQUEUE
	}

	if name, err = createInterface(fd, config.Name, flags); err != nil {
		return "", err
	}

	if err = setDeviceOptions(fd, config); err != nil {
		return "", err
	}

	return name, nil
}

func createInterface(fd uintptr, ifName string, flags uint16) (createdIFName string, err error) {
	var req ifReq
	req.Flags = flags
	copy(req.Name[:], ifName)

	err = ioctl(fd, syscall.TUNSETIFF, uintptr(unsafe.Pointer(&req))) // #nosec G103 -- This is sadly required for now
	if err != nil {
		return
	}

	createdIFName = strings.Trim(string(req.Name[:]), "\x00")
	return
}

func setDeviceOptions(fd uintptr, config Config) (err error) {
	if config.Permissions != nil {
		if err = ioctl(fd, syscall.TUNSETOWNER, uintptr(config.Permissions.Owner)); err != nil {
			return
		}
		if err = ioctl(fd, syscall.TUNSETGROUP, uintptr(config.Permissions.Group)); err != nil {
			return
		}
	}

	// set clear the persist flag
	value := 0
	if config.Persist {
		value = 1
	}
	return ioctl(fd, syscall.TUNSETPERSIST, uintptr(value))
}

func openDev(config Config) (ifce *Interface, err error) {
	var fdInt int
	if fdInt, err = syscall.Open(
		"/dev/net/tun", os.O_RDWR|syscall.O_NONBLOCK, 0); err != nil {
		return nil, err
	}

	name, err := setupFd(config, uintptr(fdInt))
	if err != nil {
		return nil, err
	}

	return &Interface{
		isTAP:           config.DeviceType == TAP,
		ReadWriteCloser: os.NewFile(uintptr(fdInt), "tun"),
		name:            name,
	}, nil
}

func (ifce *Interface) SetMTU(mtu int) error {
	return exec.Command("ip", "link", "set", "dev", ifce.name, "mtu", fmt.Sprintf("%d", mtu)).Run() // #nosec G204 -- This is exactly what it needs to be
}

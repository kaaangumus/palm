//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// ioctlReadTermios is TCGETS on Linux: the ioctl that answers "is this a
// terminal?". Stat alone is not enough because /dev/null is a character device
// too, so a redirected run would look interactive.
const ioctlReadTermios = 0x5401

func isTerminal(f *os.File) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(ioctlReadTermios),
		uintptr(unsafe.Pointer(&termios)),
		0, 0, 0,
	)
	return errno == 0
}

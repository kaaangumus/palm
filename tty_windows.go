//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
)

// isTerminal asks the console whether the handle is a real terminal. A handle
// redirected to NUL fails the call, which is exactly what auto-save needs.
func isTerminal(f *os.File) bool {
	var mode uint32
	ok, _, _ := procGetConsoleMode.Call(f.Fd(), uintptr(unsafe.Pointer(&mode)))
	return ok != 0
}

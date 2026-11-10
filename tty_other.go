//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !windows

package main

import "os"

// Fallback for platforms without an ioctl probe: treat a character device that
// is not the null device as a terminal.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return f.Name() != os.DevNull
}

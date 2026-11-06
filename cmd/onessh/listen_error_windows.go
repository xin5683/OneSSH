//go:build windows

package main

import (
	"errors"
	"syscall"
)

const windowsWSAEADDRINUSE syscall.Errno = 10048

func isAddressInUse(err error) bool {
	// syscall.EADDRINUSE 是 Go 在 Windows 上定义的通用错误；
	// 网络栈实际返回的是 Winsock 的 WSAEADDRINUSE(10048)。
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, windowsWSAEADDRINUSE)
}

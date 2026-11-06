package main

import (
	"fmt"
	"net"
	"net/url"
	"runtime"
)

// browserURL 把实际监听地址转换成用户可直接打开的本地 HTTP 地址。
func browserURL(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "http://" + address
	}
	ip := net.ParseIP(host)
	if host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return (&url.URL{Scheme: "http", Host: net.JoinHostPort(host, port)}).String()
}

func listenFailureMessage(address string, err error) string {
	reason := err.Error()
	if isAddressInUse(err) {
		reason = "端口已被占用"
	}
	message := fmt.Sprintf(
		"无法监听 %s: %s\n请关闭占用该端口的进程，或修改 .env 中的 ONESSH_LISTEN 后重启。",
		address,
		reason,
	)
	if runtime.GOOS == "windows" {
		if _, port, splitErr := net.SplitHostPort(address); splitErr == nil {
			message += fmt.Sprintf("\n查找占用进程: netstat -ano | findstr :%s", port)
		}
	}
	return message
}

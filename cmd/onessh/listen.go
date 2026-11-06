package main

import (
	"fmt"
	"net"
	"net/url"
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
	return fmt.Sprintf(
		"无法监听 %s: %v\n端口可能已被其他程序占用。请关闭占用该端口的进程，或修改 .env 中的 ONESSH_LISTEN 后重启。",
		address,
		err,
	)
}

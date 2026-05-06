//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func listenTCP(port int, proxyMode string) (*net.TCPListener, error) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	if proxyMode != "tproxy" {
		return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: port})
	}

	listenConfig := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}

	listener, err := listenConfig.Listen(context.Background(), "tcp4", addr)
	if err != nil {
		return nil, err
	}

	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		listener.Close()
		return nil, fmt.Errorf("listener is %T, expected *net.TCPListener", listener)
	}
	return tcpListener, nil
}

func getOriginalDst(conn *net.TCPConn, proxyMode string) (*net.TCPAddr, error) {
	if proxyMode == "tproxy" {
		return getTProxyOriginalDst(conn)
	}
	return getRedirectOriginalDst(conn)
}

// getRedirectOriginalDst 获取被 REDIRECT 规则重定向前的原始目标地址
// 使用 SO_ORIGINAL_DST socket 选项，这是 iptables REDIRECT 目标填充的
func getRedirectOriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, fmt.Errorf("failed to get file descriptor: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// SO_ORIGINAL_DST = 80
	const SO_ORIGINAL_DST = 80

	// 使用 sockaddr 结构获取原始目标地址
	var addr unix.RawSockaddrInet4
	addrLen := uint32(unsafe.Sizeof(addr))

	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_IP),
		uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)

	if errno != 0 {
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: %v", errno)
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(addr.Port>>8 | addr.Port<<8)
	logrus.Debugf("[Tproxy] getOriginalDst raw value: %d, parsed port: %d", addr.Port, port)
	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}, nil
}

// getTProxyOriginalDst 获取 TPROXY 保留的原始目标地址。
// TCP TPROXY 不做 NAT，内核会把原始目的地址保留为 accepted socket 的本地地址。
func getTProxyOriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	addr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("local address is %T, expected *net.TCPAddr", conn.LocalAddr())
	}
	if addr.IP == nil || addr.IP.IsUnspecified() || addr.Port == 0 {
		return nil, fmt.Errorf("invalid TPROXY original destination: %s", addr.String())
	}
	return addr, nil
}

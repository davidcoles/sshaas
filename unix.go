//go:build !windows

package main

import (
	"net"
	"os"
)

func dial() (net.Conn, error) {
	return net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
}

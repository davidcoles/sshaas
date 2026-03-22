//go:build windows

package main

import (
	"context"
	"io"
	"os"

	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

func dial() (io.ReadWriter, error) {
	path := `\\.\pipe\openssh-ssh-agent`

	if ssh_auth_sock := os.Getenv("SSH_AUTH_SOCK"); ssh_auth_sock != "" {
		path = ssh_auth_sock
	}

	return namedpipe.DialContext(context.Background(), path)
}

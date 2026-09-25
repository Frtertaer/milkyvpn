//go:build !windows

package tun

import "fmt"

type noDevice struct{}

func openDevice(cfg *Config) (Device, error) {
	return nil, fmt.Errorf("tun: unsupported platform")
}

func IsElevated() bool { return false }

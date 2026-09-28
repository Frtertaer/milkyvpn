//go:build !windows && !linux && !darwin

package tun

import "fmt"

func openDevice(cfg *Config) (Device, error) {
	return nil, fmt.Errorf("tun: unsupported platform")
}

func IsElevated() bool { return false }

package tun

// Device is the platform TUN adapter plus its routing configuration.
type Device interface {
	// MTU is the adapter MTU handed to the userspace stack.
	MTU() uint32
	// ReadPacket blocks until a packet arrives. release must be called to
	// return the ring slot.
	ReadPacket() (pkt []byte, release func(), err error)
	// WritePacket injects a packet back into the OS.
	WritePacket(pkt []byte) error
	// Configure assigns the interface address and installs routes. Needs
	// administrator rights on Windows.
	Configure(serverIPs []string) error
	// Restore removes the routes Configure installed (best effort).
	Restore()
	// Close tears down the adapter and its session.
	Close() error
}

const defaultMTU = 1500

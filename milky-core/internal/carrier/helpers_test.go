package carrier

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
)

func rsaGenerate() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func bytesContain(h, n []byte) bool { return bytes.Contains(h, n) }

package kal2core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateKeypair returns (priv64hex, pub32hex) ed25519 server identity.
func GenerateKeypairHex() (privHex, pubHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(priv), hex.EncodeToString(pub), nil
}

// DecodeKeyHex is a strict hex variant for scripts.
func DecodeKeyHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("need 64 hex chars")
	}
	return b, nil
}

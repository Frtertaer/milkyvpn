package carrier

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/cryptobyte"
)

// echConfigVersion is the draft-ietf-tls-esni ECHConfig version marker (also
// the extension codepoint for encrypted_client_hello).
const echConfigVersion uint16 = 0xfe0d

const (
	echKEMX25519  uint16 = 0x0020 // DHKEM(X25519, HKDF-SHA256)
	echKDFSHA256  uint16 = 0x0001
	echAES128GCM  uint16 = 0x0001
	echAES256GCM  uint16 = 0x0002
	echChaChaPoly uint16 = 0x0003
)

// MarshalECHConfig renders one ECHConfig for publicName (the cover name carried
// in the outer ClientHello; the real SNI travels encrypted inside).
func MarshalECHConfig(configID uint8, pubKey []byte, publicName string) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(echConfigVersion)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(configID)
		b.AddUint16(echKEMX25519)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(pubKey)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, aead := range []uint16{echAES128GCM, echAES256GCM, echChaChaPoly} {
				b.AddUint16(echKDFSHA256)
				b.AddUint16(aead)
			}
		})
		b.AddUint8(0) // maximum_name_length: no padding cap
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(publicName))
		})
		b.AddUint16(0) // extensions
	})
	return b.BytesOrPanic()
}

// ECHConfigListFromConfig wraps one ECHConfig into the ECHConfigList clients
// take (link param / utls EncryptedClientHelloConfigList).
func ECHConfigListFromConfig(cfg []byte) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(cfg)
	})
	return b.BytesOrPanic()
}

// GenerateECHConfig mints an X25519-HKDF-SHA256 ECH keypair and returns the
// client-facing ECHConfigList plus the server-side key entry.
func GenerateECHConfig(publicName string) (list []byte, key tls.EncryptedClientHelloKey, err error) {
	kem := hpke.DHKEM(ecdh.X25519())
	priv, err := kem.GenerateKey()
	if err != nil {
		return nil, key, fmt.Errorf("ech keygen: %w", err)
	}
	privBytes, err := priv.Bytes()
	if err != nil {
		return nil, key, fmt.Errorf("ech keygen: %w", err)
	}
	var id [1]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, key, fmt.Errorf("ech keygen: %w", err)
	}
	cfg := MarshalECHConfig(id[0], priv.PublicKey().Bytes(), publicName)
	return ECHConfigListFromConfig(cfg), tls.EncryptedClientHelloKey{
		Config:      cfg,
		PrivateKey:  privBytes,
		SendAsRetry: true,
	}, nil
}

// echPublicName extracts public_name from one marshalled ECHConfig.
func echPublicName(cfg []byte) (string, error) {
	s := cryptobyte.String(cfg)
	var version, length uint16
	if !s.ReadUint16(&version) || !s.ReadUint16(&length) || version != echConfigVersion {
		return "", fmt.Errorf("ech: bad config header")
	}
	var id uint8
	var kem uint16
	var pubKey cryptobyte.String
	var suites cryptobyte.String
	var maxName uint8
	var publicName cryptobyte.String
	if !s.ReadUint8(&id) || !s.ReadUint16(&kem) ||
		!s.ReadUint16LengthPrefixed(&pubKey) ||
		!s.ReadUint16LengthPrefixed(&suites) ||
		!s.ReadUint8(&maxName) ||
		!s.ReadUint8LengthPrefixed(&publicName) {
		return "", fmt.Errorf("ech: malformed config")
	}
	return string(publicName), nil
}

// echKeyFile is the on-disk server format: hex ECHConfig + hex HPKE private key.
type echKeyFile struct {
	Config     string `json:"config"`      // hex marshalled ECHConfig
	PrivateKey string `json:"private_key"` // hex HPKE private key
	PublicName string `json:"public_name"` // informational
}

// SaveECHKeyFile persists the server side of GenerateECHConfig.
func SaveECHKeyFile(path, publicName string, key tls.EncryptedClientHelloKey) error {
	payload, err := json.MarshalIndent(echKeyFile{
		Config:     hex.EncodeToString(key.Config),
		PrivateKey: hex.EncodeToString(key.PrivateKey),
		PublicName: publicName,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0600)
}

// LoadECHKeys loads one or more ECH key files for the server TLS config.
func LoadECHKeys(paths []string) ([]tls.EncryptedClientHelloKey, error) {
	var keys []tls.EncryptedClientHelloKey
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var kf echKeyFile
		if err := json.Unmarshal(raw, &kf); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		cfg, err := hex.DecodeString(kf.Config)
		if err != nil {
			return nil, fmt.Errorf("%s: bad config hex", p)
		}
		priv, err := hex.DecodeString(kf.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("%s: bad private key hex", p)
		}
		keys = append(keys, tls.EncryptedClientHelloKey{
			Config:      cfg,
			PrivateKey:  priv,
			SendAsRetry: true,
		})
	}
	return keys, nil
}

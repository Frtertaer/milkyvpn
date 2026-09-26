package carrier

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// PeekClientHelloSNI reads one TLS record containing a ClientHello from r and
// returns the consumed bytes plus the SNI server name ("" when absent). The
// returned bytes must be pushed back onto the connection before handing it to
// the TLS stack or splicing it upstream.
func PeekClientHelloSNI(r io.Reader) (consumed []byte, sni string, err error) {
	// TLS record header: type(1) version(2) length(2)
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return nil, "", err
	}
	if hdr[0] != 0x16 { // handshake record
		return hdr, "", fmt.Errorf("not a TLS handshake record")
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 4 || recLen > 16384+2048 {
		return hdr, "", fmt.Errorf("bad record length")
	}
	body := make([]byte, recLen)
	if _, err = io.ReadFull(r, body); err != nil {
		return nil, "", err
	}
	consumed = append(hdr, body...)
	// Handshake: type(1) len(3)
	if body[0] != 0x01 {
		return consumed, "", fmt.Errorf("not a ClientHello")
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if hsLen+4 > len(body) {
		hsLen = len(body) - 4
	}
	sni = parseSNI(body[4 : 4+hsLen])
	return consumed, sni, nil
}

// parseSNI walks the ClientHello body for the server_name extension.
func parseSNI(b []byte) string {
	// version(2) random(32)
	if len(b) < 34 {
		return ""
	}
	b = b[34:]
	if len(b) < 1 {
		return ""
	}
	sidLen := int(b[0])
	b = b[1:]
	if len(b) < sidLen+2 {
		return ""
	}
	b = b[sidLen:]
	csLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < csLen+1 {
		return ""
	}
	b = b[csLen:]
	compLen := int(b[0])
	b = b[1:]
	if len(b) < compLen {
		return ""
	}
	b = b[compLen:]
	if len(b) < 2 {
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < extTotal {
		extTotal = len(b)
	}
	exts := b[:extTotal]
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts[:2])
		l := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if len(exts) < l {
			return ""
		}
		data := exts[:l]
		exts = exts[l:]
		if typ != 0x0000 { // server_name
			continue
		}
		// server_name_list: list_len(2) || type(1)=0 || name_len(2) || name
		if len(data) < 5 {
			return ""
		}
		nameLen := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+nameLen {
			return ""
		}
		return string(data[5 : 5+nameLen])
	}
	return ""
}

var errPeekTimeout = errors.New("peek timeout")

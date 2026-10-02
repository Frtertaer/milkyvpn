package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// RFC 6238 TOTP (HMAC-SHA1, 30s step, 6 digits) — Google Authenticator /
// Aegis / any standard app compatible. The secret is stored hex-encoded in
// panel.json; the pending secret lives only in memory until enable-time.

func totpCode(secret []byte, t time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix())/30)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 |
		uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", code%1000000)
}

// totpVerify accepts the current and one adjacent step on each side — small
// clock drift between panel host and phone is expected.
func totpVerify(secret []byte, code string) bool {
	if len(code) != 6 {
		return false
	}
	now := time.Now()
	for _, dt := range []time.Duration{-30, 0, 30} {
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, now.Add(dt*time.Second))), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpNewSecret() ([]byte, string) {
	var b [20]byte
	_, _ = rand.Read(b[:])
	return b[:], base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
}

func totpURI(b32, issuer, account string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		url.PathEscape(issuer), url.PathEscape(account), b32, url.QueryEscape(issuer))
}

// milkynative is the unified C ABI over the kal2 core — the same exported
// symbols link into every client platform:
//
//	Android   libmilky.so      (JNI side keeps kal2native names; this ABI is
//	                           what the :kal2 service will move to)
//	iOS       Milky.xcframework static archive
//	Windows   milky.dll
//	macOS     libmilky.dylib
//	Linux     libmilky.so
//
// Everything crosses as plain C (int / char* / a log callback) so Dart FFI,
// Swift and JNI can all call it without a glue layer per language.
//
// config JSON keys — see pkg/kal2mobile/mobile.go for the authoritative list
// (addr, sni, carrier, path, pub, psk, socks, ech, cover, tun, tun_fd).
package main

/*
#include <stdlib.h>
#include <string.h>

typedef void (*milky_log_cb)(const char* msg);
static milky_log_cb milkyLogCb = NULL;
static void milkySetLogCb(milky_log_cb cb) { milkyLogCb = cb; }
static void milkyEmitLog(const char* msg) { if (milkyLogCb) milkyLogCb(msg); }
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/Frtertaer/milkyvpn/milky-core/pkg/kal2mobile"
)

var (
	errMu   sync.Mutex
	lastErr string
)

func setErr(e error) {
	errMu.Lock()
	defer errMu.Unlock()
	if e == nil {
		lastErr = ""
	} else {
		lastErr = e.Error()
	}
}

//export milky_start
func milky_start(configJSON *C.char) C.int {
	if configJSON == nil {
		setErr(errors.New("milky_start: null config"))
		return -1
	}
	port, err := kal2mobile.Start(C.GoString(configJSON))
	setErr(err)
	if err != nil {
		return -1
	}
	return C.int(port)
}

//export milky_stop
func milky_stop() {
	kal2mobile.Stop()
	setErr(nil)
}

//export milky_alive
func milky_alive() C.int {
	if kal2mobile.Alive() {
		return 1
	}
	return 0
}

//export milky_last_error
func milky_last_error(buf *C.char, cap C.int) C.int {
	errMu.Lock()
	defer errMu.Unlock()
	if buf == nil || cap <= 0 {
		return -1
	}
	msg := lastErr
	n := len(msg)
	if n > int(cap)-1 {
		n = int(cap) - 1
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(cap))
	copy(out, msg[:n])
	out[n] = 0
	return C.int(n)
}

//export milky_set_log_callback
func milky_set_log_callback(cb C.milky_log_cb) {
	C.milkySetLogCb(cb)
	if cb == nil {
		kal2mobile.SetLogger(nil)
		return
	}
	kal2mobile.SetLogger(func(msg string) {
		c := C.CString(msg)
		C.milkyEmitLog(c)
		C.free(unsafe.Pointer(c))
	})
}

// versionC is allocated once — milky_version callers never free it.
var versionC = C.CString("milky-core/2.1 (kal2)")

//export milky_version
func milky_version() *C.char {
	return versionC
}

func main() {}

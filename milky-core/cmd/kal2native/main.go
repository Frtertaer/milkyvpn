// kal2native is the JNI entry point of libcore.so for Android. Built with
// -buildmode=c-shared; the Kotlin side calls these via
// homes.milky.vpn.bridge.NativeBridge externals. Only string/int/bool cross JNI —
// all session logic lives in kal2mobile.
package main

/*
#cgo LDFLAGS: -llog
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>

static const char* jniGetStr(JNIEnv* env, jstring s) {
    if (s == NULL) return NULL;
    return (*env)->GetStringUTFChars(env, s, NULL);
}
static void jniRelStr(JNIEnv* env, jstring s, const char* p) {
    if (s != NULL && p != NULL) (*env)->ReleaseStringUTFChars(env, s, p);
}
static jstring jniNewStr(JNIEnv* env, const char* p) {
    return (*env)->NewStringUTF(env, p == NULL ? "" : p);
}
static void jniLog(const char* tag, const char* msg) {
    __android_log_write(ANDROID_LOG_INFO, tag, msg);
}

// Unified C ABI (milky.h) — the same exports libmilky ships on desktop
// and iOS, so Dart FFI callers can use one binding on every platform
// alongside the JNI entry points below.
typedef void (*milky_log_cb)(const char* msg);
static milky_log_cb milkyLogCb = NULL;
static void milkySetLogCb(milky_log_cb cb) { milkyLogCb = cb; }
static void milkyEmitLog(const char* msg) { if (milkyLogCb) milkyLogCb(msg); }
*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/Frtertaer/milkyvpn/milky-core/pkg/kal2mobile"
)

var lastErr string

func setErr(e error) {
	if e == nil {
		lastErr = ""
	} else {
		lastErr = e.Error()
	}
}

func init() {
	kal2mobile.SetLogger(func(msg string) {
		tag := C.CString("core")
		c := C.CString(msg)
		C.jniLog(tag, c)
		// FFI receivers decode the pointer asynchronously — keep it
		// alive (see cmd/milkynative; log volume is small).
		C.milkyEmitLog(C.CString(msg))
		C.free(unsafe.Pointer(tag))
		C.free(unsafe.Pointer(c))
	})
}

//export Java_homes_milky_vpn_bridge_NativeBridge_nativeStart
func Java_homes_milky_vpn_bridge_NativeBridge_nativeStart(env *C.JNIEnv, _ C.jclass, cfg C.jstring) C.jint {
	c := C.jniGetStr(env, cfg)
	if c == nil {
		setErr(errors.New("config string null"))
		return -1
	}
	json := C.GoString(c)
	C.jniRelStr(env, cfg, c)
	port, err := kal2mobile.Start(json)
	setErr(err)
	if err != nil {
		return -1
	}
	return C.jint(port)
}

//export Java_homes_milky_vpn_bridge_NativeBridge_nativeStop
func Java_homes_milky_vpn_bridge_NativeBridge_nativeStop(env *C.JNIEnv, cls C.jclass) {
	kal2mobile.Stop()
}

//export Java_homes_milky_vpn_bridge_NativeBridge_nativeAlive
func Java_homes_milky_vpn_bridge_NativeBridge_nativeAlive(env *C.JNIEnv, cls C.jclass) C.jboolean {
	if kal2mobile.Alive() {
		return C.JNI_TRUE
	}
	return C.JNI_FALSE
}

//export Java_homes_milky_vpn_bridge_NativeBridge_nativeLastError
func Java_homes_milky_vpn_bridge_NativeBridge_nativeLastError(env *C.JNIEnv, cls C.jclass) C.jstring {
	cs := C.CString(lastErr)
	s := C.jniNewStr(env, cs)
	C.free(unsafe.Pointer(cs))
	return s
}

var versionC = C.CString("milky-core/2.1 (kal2)")

//export milky_start
func milky_start(cjson *C.char) C.int {
	port, err := kal2mobile.Start(C.GoString(cjson))
	setErr(err)
	if err != nil {
		return -1
	}
	return C.int(port)
}

//export milky_stop
func milky_stop() {
	kal2mobile.Stop()
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
	if buf == nil || cap <= 0 {
		return -1
	}
	n := len(lastErr)
	if n > int(cap)-1 {
		n = int(cap) - 1
	}
	if n > 0 {
		C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(unsafe.StringData(lastErr)), C.size_t(n))
	}
	*(*C.char)(unsafe.Add(unsafe.Pointer(buf), n)) = 0
	return C.int(n)
}

//export milky_set_log_callback
func milky_set_log_callback(cb C.milky_log_cb) {
	C.milkySetLogCb(cb)
}

//export milky_version
func milky_version() *C.char {
	return versionC
}

func main() {}

// kal2native is the JNI entry point of libkal2.so for Android. Built with
// -buildmode=c-shared; the Kotlin side calls these via
// homes.milky.vpn.kal2.Kal2Core externals. Only string/int/bool cross JNI —
// all session logic lives in kal2mobile.
package main

/*
#cgo LDFLAGS: -llog
#include <jni.h>
#include <stdlib.h>
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
		tag := C.CString("kal2")
		c := C.CString(msg)
		C.jniLog(tag, c)
		C.free(unsafe.Pointer(tag))
		C.free(unsafe.Pointer(c))
	})
}

//export Java_homes_milky_vpn_kal2_Kal2Core_nativeStart
func Java_homes_milky_vpn_kal2_Kal2Core_nativeStart(env *C.JNIEnv, _ C.jclass, cfg C.jstring) C.jint {
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

//export Java_homes_milky_vpn_kal2_Kal2Core_nativeStop
func Java_homes_milky_vpn_kal2_Kal2Core_nativeStop(env *C.JNIEnv, cls C.jclass) {
	kal2mobile.Stop()
}

//export Java_homes_milky_vpn_kal2_Kal2Core_nativeAlive
func Java_homes_milky_vpn_kal2_Kal2Core_nativeAlive(env *C.JNIEnv, cls C.jclass) C.jboolean {
	if kal2mobile.Alive() {
		return C.JNI_TRUE
	}
	return C.JNI_FALSE
}

//export Java_homes_milky_vpn_kal2_Kal2Core_nativeLastError
func Java_homes_milky_vpn_kal2_Kal2Core_nativeLastError(env *C.JNIEnv, cls C.jclass) C.jstring {
	cs := C.CString(lastErr)
	s := C.jniNewStr(env, cs)
	C.free(unsafe.Pointer(cs))
	return s
}

func main() {}

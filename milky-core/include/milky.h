/* milky.h — unified C ABI of the kal2 core (libmilky.so / milky.dll /
 * libmilky.dylib / Milky.xcframework). One binary per platform, one ABI for
 * Dart FFI, Swift/ObjC, JNI and plain C.
 *
 * Config is a JSON string — keys documented in pkg/kal2mobile/mobile.go:
 *   {"addr":"ip:443[,...]", "sni":"kal.example.dev", "carrier":"auto",
 *    "path":"/api/v2/stream", "pub":"<hex>", "psk":"<hex>",
 *    "socks":"127.0.0.1:10808", "ech":"<base64>", "cover":true,
 *    "tun":false, "tun_fd":0, "tun_addr":"10.85.0.1"}
 */
#ifndef MILKY_H
#define MILKY_H

#ifdef __cplusplus
extern "C" {
#endif

/* Connect with the JSON config and start the local SOCKS5 proxy.
 * Returns the SOCKS listen port (e.g. 10808), or -1 on failure —
 * read the reason with milky_last_error. */
int milky_start(const char *config_json);

/* Tear the session down. Idempotent. */
void milky_stop(void);

/* 1 while a session is connected, 0 otherwise. */
int milky_alive(void);

/* Copy the last error into buf (NUL-terminated). Returns bytes written,
 * or -1 when buf/cap are unusable. An empty string means no error. */
int milky_last_error(char *buf, int cap);

/* Receive 'kal2: ...' log lines. cb may be NULL to detach. For Dart FFI:
 * NativeCallable<...>.listener.nativeFunction. */
typedef void (*milky_log_cb)(const char *msg);
void milky_set_log_callback(milky_log_cb cb);

/* Static string — never free. */
const char *milky_version(void);

#ifdef __cplusplus
}
#endif
#endif /* MILKY_H */

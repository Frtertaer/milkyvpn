import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// FFI binding to the unified milky C ABI (`include/milky.h`).
///
/// One surface on every platform: `milky.dll` on Windows, `libmilky.so` on
/// Linux/Android (the Android :kal2 libcore.so exports the same symbols
/// alongside JNI), `libmilky.dylib`/`Milky.xcframework` on macOS/iOS.
/// All session logic lives in the Go runtime; this is a thin loader.
class MilkyCore {
  MilkyCore._(DynamicLibrary lib)
    : _lib = lib,
      _start = lib
          .lookup<NativeFunction<Int32 Function(Pointer<Utf8>)>>(
            'milky_start',
          )
          .asFunction(),
      _stop = lib
          .lookup<NativeFunction<Void Function()>>('milky_stop')
          .asFunction(),
      _alive = lib
          .lookup<NativeFunction<Int32 Function()>>('milky_alive')
          .asFunction(),
      _lastError = lib
          .lookup<NativeFunction<
            Int32 Function(Pointer<Utf8>, Int32)
          >>('milky_last_error')
          .asFunction(),
      _setLogCb = lib
          .lookup<NativeFunction<
            Void Function(Pointer<NativeFunction<MilkyLogCbNative>>)
          >>('milky_set_log_callback')
          .asFunction(),
      _version = lib
          .lookup<NativeFunction<Pointer<Utf8> Function()>>('milky_version')
          .asFunction();

  // Keeps the library loaded for the object's lifetime.
  // ignore: unused_field
  final DynamicLibrary _lib;
  final int Function(Pointer<Utf8>) _start;
  final void Function() _stop;
  final int Function() _alive;
  final int Function(Pointer<Utf8>, int) _lastError;
  final void Function(Pointer<NativeFunction<MilkyLogCbNative>>) _setLogCb;
  final Pointer<Utf8> Function() _version;

  NativeCallable<MilkyLogCbNative>? _logCallable;

  /// Resolves the core library for the current platform.
  ///
  /// Search order on desktop: an explicit [path], then `milky.dll` /
  /// `libmilky.so` / `libmilky.dylib` beside the executable, then a
  /// `kal2/` subdirectory (matches the Windows package layout). On iOS the
  /// xcframework is statically linked → the process image itself.
  /// On Android `libcore.so` is already loaded by `NativeBridge`.
  static MilkyCore open({String? path}) {
    if (Platform.isIOS || Platform.isAndroid) {
      return MilkyCore._(DynamicLibrary.process());
    }
    final exeDir = File(Platform.resolvedExecutable).parent.path;
    final names = Platform.isWindows
        ? const ['milky.dll']
        : Platform.isMacOS
        ? const ['libmilky.dylib']
        : const ['libmilky.so'];
    final candidates = <String>[
      if (path != null) path,
      for (final n in names) ...[
        '$exeDir/$n',
        '$exeDir/kal2/$n',
        n, // let the OS loader search standard paths
      ],
    ];
    Object? lastErr;
    for (final c in candidates) {
      try {
        return MilkyCore._(DynamicLibrary.open(c));
      } on Object catch (e) {
        lastErr = e;
      }
    }
    throw MilkyCoreException('cannot load core library', '$lastErr');
  }

  /// Start the session with the JSON config (see kal2mobile). Returns the
  /// local SOCKS5 port; throws [MilkyCoreException] with `milky_last_error`
  /// text on failure.
  int start(String configJson) {
    final c = configJson.toNativeUtf8();
    try {
      final port = _start(c);
      if (port < 0) {
        throw MilkyCoreException('start', lastError());
      }
      return port;
    } finally {
      malloc.free(c);
    }
  }

  void stop() => _stop();

  bool get alive => _alive() == 1;

  String lastError() {
    final buf = malloc.allocate<Utf8>(1024);
    try {
      final n = _lastError(buf, 1024);
      return n < 0 ? '' : buf.toDartString(length: n);
    } finally {
      malloc.free(buf);
    }
  }

  String get version => _version().toDartString();

  /// 'kal2: ...' log lines. Pass null to detach. The callable is kept alive
  /// on this object — safe as long as the MilkyCore instance lives.
  void setLogCallback(void Function(String line)? cb) {
    _logCallable?.close();
    _logCallable = null;
    if (cb == null) {
      _setLogCb(nullptr);
      return;
    }
    final callable = NativeCallable<MilkyLogCbNative>.listener((Pointer<Utf8> p) {
      cb(p.toDartString());
    });
    _logCallable = callable;
    _setLogCb(callable.nativeFunction);
  }

  void dispose() {
    setLogCallback(null);
  }
}

typedef MilkyLogCbNative = Void Function(Pointer<Utf8>);

class MilkyCoreException implements Exception {
  MilkyCoreException(this.op, this.detail);
  final String op;
  final String detail;
  @override
  String toString() => 'MilkyCoreException($op: $detail)';
}

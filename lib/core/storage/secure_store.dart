import 'dart:convert';
import 'dart:io' show File, FileSystemException;

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Abstraction over secret storage so the domain layer can be unit-tested without a platform.
abstract class SecureStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
  Future<void> deleteAll();
}

/// Android Keystore-backed implementation (flutter_secure_storage: AES-GCM data key wrapped by a
/// Keystore key). Backups are disabled by the manifest rules, so secrets never leave the device.
class KeystoreSecureStore implements SecureStore {
  KeystoreSecureStore()
    : _s = const FlutterSecureStorage(
        aOptions: AndroidOptions(
          resetOnError: true,
          storageNamespace: 'milkyvpn_secure',
          preferencesKeyPrefix: 'mv',
        ),
      );

  final FlutterSecureStorage _s;

  @override
  Future<String?> read(String key) => _s.read(key: key);

  @override
  Future<void> write(String key, String value) =>
      _s.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _s.delete(key: key);

  @override
  Future<void> deleteAll() => _s.deleteAll();
}

/// JSON file inside the app's container. On sandboxed macOS an unsigned
/// (ad-hoc) build cannot touch the keychain at all, so this is the only
/// working backend there; the container ACL keeps the file private to the app.
class FileSecureStore implements SecureStore {
  FileSecureStore(this._file);

  final File _file;

  Future<Map<String, String>> _load() async {
    try {
      final decoded = jsonDecode(await _file.readAsString());
      if (decoded is! Map) return {};
      return {
        for (final e in decoded.entries)
          if (e.value is String) e.key as String: e.value as String,
      };
    } catch (_) {
      return {};
    }
  }

  Future<void> _save(Map<String, String> data) async {
    await _file.parent.create(recursive: true);
    await _file.writeAsString(jsonEncode(data), flush: true);
  }

  @override
  Future<String?> read(String key) async => (await _load())[key];

  @override
  Future<void> write(String key, String value) async {
    final data = await _load();
    data[key] = value;
    await _save(data);
  }

  @override
  Future<void> delete(String key) async {
    final data = await _load();
    if (data.remove(key) != null) await _save(data);
  }

  @override
  Future<void> deleteAll() async {
    try {
      await _file.delete();
    } on FileSystemException {
      // Missing file is already empty.
    }
  }
}

/// Tries [primary] (keychain) first and routes to [backup] when the platform
/// refuses the operation — e.g. SecItemAdd returning OSStatus -34018 on a
/// sandboxed macOS build that is signed ad-hoc without keychain-access-groups.
/// Signed builds keep using the keychain; the backup is only touched on failure.
class FallbackSecureStore implements SecureStore {
  FallbackSecureStore({
    required SecureStore primary,
    required SecureStore backup,
  }) : _primary = primary,
       _backup = backup;

  final SecureStore _primary;
  final SecureStore _backup;

  @override
  Future<String?> read(String key) async {
    try {
      final value = await _primary.read(key);
      if (value != null) return value;
    } catch (_) {
      // Primary refused; the backup may still hold the value.
    }
    return _backup.read(key);
  }

  @override
  Future<void> write(String key, String value) async {
    try {
      await _primary.write(key, value);
      return;
    } catch (_) {
      // Primary refused; drop any stale primary copy so it cannot shadow
      // the backup on later reads, then persist via the backup.
    }
    try {
      await _primary.delete(key);
    } catch (_) {}
    await _backup.write(key, value);
  }

  @override
  Future<void> delete(String key) async {
    try {
      await _primary.delete(key);
    } catch (_) {}
    await _backup.delete(key);
  }

  @override
  Future<void> deleteAll() async {
    try {
      await _primary.deleteAll();
    } catch (_) {}
    await _backup.deleteAll();
  }
}

/// In-memory implementation for tests.
class MemorySecureStore implements SecureStore {
  final Map<String, String> data = {};

  @override
  Future<String?> read(String key) async => data[key];

  @override
  Future<void> write(String key, String value) async => data[key] = value;

  @override
  Future<void> delete(String key) async => data.remove(key);

  @override
  Future<void> deleteAll() async => data.clear();
}

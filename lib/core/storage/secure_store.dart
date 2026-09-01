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
  Future<void> write(String key, String value) => _s.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _s.delete(key: key);

  @override
  Future<void> deleteAll() => _s.deleteAll();
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

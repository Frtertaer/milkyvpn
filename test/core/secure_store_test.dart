import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';

class _ThrowingStore implements SecureStore {
  final List<String> calls = [];

  @override
  Future<String?> read(String key) {
    calls.add('read:$key');
    throw Exception('OSStatus -34018');
  }

  @override
  Future<void> write(String key, String value) {
    calls.add('write:$key');
    throw Exception('OSStatus -34018');
  }

  @override
  Future<void> delete(String key) {
    calls.add('delete:$key');
    throw Exception('OSStatus -34018');
  }

  @override
  Future<void> deleteAll() {
    calls.add('deleteAll');
    throw Exception('OSStatus -34018');
  }
}

void main() {
  group('FallbackSecureStore', () {
    test('write falls back to the backup when the primary refuses', () async {
      final primary = _ThrowingStore();
      final backup = MemorySecureStore();
      final store = FallbackSecureStore(primary: primary, backup: backup);

      await store.write('k', 'v');

      expect(backup.data, {'k': 'v'});
      expect(await store.read('k'), 'v');
    });

    test(
      'read returns the primary value without touching the backup',
      () async {
        final primary = MemorySecureStore()..data['k'] = 'p';
        final backup = MemorySecureStore()..data['k'] = 'b';
        final store = FallbackSecureStore(primary: primary, backup: backup);

        expect(await store.read('k'), 'p');
      },
    );

    test('read falls through to the backup on primary failure', () async {
      final backup = MemorySecureStore()..data['k'] = 'b';
      final store = FallbackSecureStore(
        primary: _ThrowingStore(),
        backup: backup,
      );

      expect(await store.read('k'), 'b');
    });

    test('a stale primary copy does not shadow a fallback write', () async {
      final primary = MemorySecureStore();
      final backup = MemorySecureStore();
      var broken = true;
      final flaky = _FlakyStore(primary, () => broken);
      final store = FallbackSecureStore(primary: flaky, backup: backup);

      await store.write('k', 'backup-value');
      broken = false;

      expect(await store.read('k'), 'backup-value');
    });

    test(
      'delete and deleteAll reach both stores even when primary throws',
      () async {
        final primary = _ThrowingStore();
        final backup = MemorySecureStore()..data['k'] = 'v';
        final store = FallbackSecureStore(primary: primary, backup: backup);

        await store.delete('k');
        expect(backup.data, isEmpty);

        backup.data['x'] = 'y';
        await store.deleteAll();
        expect(backup.data, isEmpty);
      },
    );
  });

  group('FileSecureStore', () {
    late Directory dir;
    late FileSecureStore store;

    setUp(() async {
      dir = await Directory.systemTemp.createTemp('secure_store_test');
      store = FileSecureStore(File('${dir.path}/nested/secure.json'));
    });

    tearDown(() async {
      if (dir.existsSync()) await dir.delete(recursive: true);
    });

    test('round-trips keys across instances', () async {
      await store.write('a', '1');
      await store.write('b', '2');

      final reopened = FileSecureStore(File('${dir.path}/nested/secure.json'));
      expect(await reopened.read('a'), '1');
      expect(await reopened.read('b'), '2');
    });

    test('delete removes one key and deleteAll clears the file', () async {
      await store.write('a', '1');
      await store.write('b', '2');
      await store.delete('a');
      expect(await store.read('a'), isNull);
      expect(await store.read('b'), '2');

      await store.deleteAll();
      expect(await store.read('b'), isNull);
    });

    test('a corrupt file reads as empty instead of throwing', () async {
      await store.write('a', '1');
      final file = File('${dir.path}/nested/secure.json');
      await file.writeAsString('not-json');

      expect(await store.read('a'), isNull);
      await store.write('b', '2');
      expect(await store.read('b'), '2');
    });
  });
}

/// Wraps [inner] and throws like an unsigned-build keychain while [broken] is
/// true, so the fallback path can be exercised against a real MemorySecureStore.
class _FlakyStore implements SecureStore {
  _FlakyStore(this._inner, this._broken);

  final SecureStore _inner;
  final bool Function() _broken;

  void _check() {
    if (_broken()) throw Exception('OSStatus -34018');
  }

  @override
  Future<String?> read(String key) {
    _check();
    return _inner.read(key);
  }

  @override
  Future<void> write(String key, String value) {
    _check();
    return _inner.write(key, value);
  }

  @override
  Future<void> delete(String key) {
    _check();
    return _inner.delete(key);
  }

  @override
  Future<void> deleteAll() {
    _check();
    return _inner.deleteAll();
  }
}

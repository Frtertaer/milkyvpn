import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';
import 'package:milkyvpn/core/subscription/subscription_repository.dart';
import 'package:milkyvpn/core/security/subscription_url_policy.dart';

void main() {
  group('SubscriptionRepository multi-source', () {
    test('multiple URLs merge profiles into one snapshot', () async {
      final store = MemorySecureStore();
      final repo = SubscriptionRepository(
        store: store,
        fetcher: _FakeFetcher(),
      );
      await repo.load();
      await repo.importFromUrl('https://one.example/sub/aaa');
      await repo.importFromUrl('https://two.example/sub/bbb');
      expect(repo.snapshot!.profiles.length, 2);
      expect(repo.redactedUrls.length, 2);
      await repo.removeUrl('https://one.example/sub/aaa');
      expect(repo.snapshot!.profiles.length, 1);
      expect(repo.snapshot!.profiles.first.remark, 'bbb-node');
      await repo.remove();
      expect(repo.hasSubscription, isFalse);
    });

    test('legacy single-url storage migrates into the urls list', () async {
      final store = MemorySecureStore();
      await store.write('subscription_url', 'https://one.example/sub/aaa');
      final repo = SubscriptionRepository(
        store: store,
        fetcher: _FakeFetcher(),
      );
      await repo.load();
      expect(repo.redactedUrls, [
        SubscriptionUrlPolicy.redact(Uri.parse('https://one.example/sub/aaa')),
      ]);
    });
  });
}

class _FakeFetcher implements SubscriptionFetcher {
  @override
  Future<FetchedSubscription> fetch(Uri url) async {
    final id = url.pathSegments.last;
    return FetchedSubscription(
      body: 'kal2://${'0' * 64}@host-$id:443#$id-node',
      headers: const {},
    );
  }
}

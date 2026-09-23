import 'subscription_repository.dart';
import 'vpn_profile.dart';

/// Truthful subscription count boundaries.
///
/// The legacy names remain available for current callers, while the explicit getters make
/// it impossible to confuse received entries, pre-dedupe parses, and retained profiles.
class SubscriptionStats {
  const SubscriptionStats({
    required this.totalLines,
    required this.profiles,
    required this.malformed,
    required this.duplicates,
    required this.compatible,
    this.countsTrusted = true,
  });

  static const SubscriptionStats empty = SubscriptionStats(
    totalLines: 0,
    profiles: 0,
    malformed: 0,
    duplicates: 0,
    compatible: 0,
  );

  factory SubscriptionStats.from(SubscriptionSnapshot? snapshot) {
    if (snapshot == null) return empty;
    return SubscriptionStats(
      totalLines: snapshot.receivedEntryCount,
      profiles: snapshot.postDedupeProfileCount,
      malformed: snapshot.malformedEntryCount,
      duplicates: snapshot.droppedDuplicateCount,
      compatible: snapshot.compatibleProfileCount,
      countsTrusted: snapshot.countsTrusted,
    );
  }

  /// Legacy alias for [receivedEntryCount].
  final int totalLines;

  /// Legacy alias for [postDedupeProfileCount].
  final int profiles;

  /// Legacy alias for [malformedEntryCount].
  final int malformed;

  /// Legacy alias for [droppedDuplicateCount].
  final int duplicates;

  /// Legacy alias for [compatibleProfileCount].
  final int compatible;

  /// False for unversioned, future-version, corrupt, or internally inconsistent snapshots.
  final bool countsTrusted;

  int get receivedEntryCount => totalLines;
  int get parsedProfileCount => profiles + duplicates;
  int get postDedupeProfileCount => profiles;
  int get droppedDuplicateCount => duplicates;
  int get malformedEntryCount => malformed;
  int get compatibleProfileCount => compatible;

  static int compatibleCount(List<VpnProfile> profiles) =>
      profiles.where((profile) => profile.isStaticCompatible).length;

  /// Every received entry resolves to malformed or parsed; every parsed entry resolves to
  /// retained or duplicate. Compatibility is a subset of retained profiles.
  bool get isAccounted =>
      receivedEntryCount >= 0 &&
      parsedProfileCount >= 0 &&
      postDedupeProfileCount >= 0 &&
      droppedDuplicateCount >= 0 &&
      malformedEntryCount >= 0 &&
      compatibleProfileCount >= 0 &&
      compatibleProfileCount <= postDedupeProfileCount &&
      receivedEntryCount == parsedProfileCount + malformedEntryCount;

  /// Numeric counts should not be presented as authoritative while this is true.
  bool get needsRefresh => !countsTrusted || !isAccounted;

  int get incompatible => postDedupeProfileCount - compatibleProfileCount;

  bool get hasDroppedEntries =>
      droppedDuplicateCount > 0 || malformedEntryCount > 0;
}

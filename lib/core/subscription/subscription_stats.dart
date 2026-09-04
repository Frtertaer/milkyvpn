import 'subscription_repository.dart';
import 'vpn_profile.dart';

/// The numbers MilkyVPN shows about a subscription, derived from what was really parsed.
///
/// Nothing here is invented: `totalLines`, `malformed`, `duplicates` come from the parser
/// and `compatible` from the same validation rules the engine applies.
class SubscriptionStats {
  const SubscriptionStats({
    required this.totalLines,
    required this.profiles,
    required this.malformed,
    required this.duplicates,
    required this.compatible,
  });

  static const SubscriptionStats empty = SubscriptionStats(totalLines: 0, profiles: 0, malformed: 0, duplicates: 0, compatible: 0);

  factory SubscriptionStats.from(SubscriptionSnapshot? s) {
    if (s == null) return empty;
    return SubscriptionStats(
      totalLines: s.totalEntries,
      profiles: s.profiles.length,
      malformed: s.malformedEntries,
      duplicates: s.duplicateEntries,
      compatible: compatibleCount(s.profiles),
    );
  }

  final int totalLines;
  final int profiles;
  final int malformed;
  final int duplicates;
  final int compatible;

  static int compatibleCount(List<VpnProfile> profiles) => profiles.where((p) => p.isStaticCompatible).length;

  /// The parser accounted for every line it saw. When this is false the UI must not claim
  /// a number it cannot explain.
  bool get isAccounted => totalLines == profiles + malformed + duplicates;

  int get incompatible => profiles - compatible;

  bool get hasDroppedEntries => duplicates > 0 || malformed > 0;
}

/// 64-bit FNV-1a hash rendered as 16 hex chars. Used only for stable, non-secret profile ids.
String fnv1a64Hex(String input) {
  // Use two 32-bit halves to stay exact on the web (no 64-bit ints in JS), and BigInt-free.
  const int prime32 = 0x01000193;
  int h1 = 0x811c9dc5; // classic 32-bit FNV offset
  int h2 = 0x050c5d1f; // second, independent seed
  for (final unit in input.codeUnits) {
    h1 = ((h1 ^ (unit & 0xff)) * prime32) & 0xffffffff;
    h1 = ((h1 ^ (unit >> 8)) * prime32) & 0xffffffff;
    h2 = ((h2 ^ (unit >> 8)) * prime32) & 0xffffffff;
    h2 = ((h2 ^ (unit & 0xff)) * prime32) & 0xffffffff;
  }
  return h1.toRadixString(16).padLeft(8, '0') + h2.toRadixString(16).padLeft(8, '0');
}

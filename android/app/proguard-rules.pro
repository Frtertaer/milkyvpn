# Xray-core gomobile binding
-keep class go.** { *; }
-keep class libv2ray.** { *; }
# Flutter
-keep class io.flutter.** { *; }
-keep class homes.milky.vpn.** { *; }
# Strip verbose logging in release
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
# Flutter deferred-components references Play Core which this app does not use.
-dontwarn com.google.android.play.core.**
-dontwarn io.flutter.embedding.engine.deferredcomponents.**
-dontwarn io.flutter.embedding.android.FlutterPlayStoreSplitApplication

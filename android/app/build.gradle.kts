import java.util.Properties

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Optional Play upload key. NEVER commit key.properties or the keystore.
// See docs/SIGNING.md for how the owner creates and configures it.
val keystorePropertiesFile = rootProject.file("key.properties")
val keystoreProperties = Properties()
val hasReleaseKeystore = keystorePropertiesFile.exists()
if (hasReleaseKeystore) {
    keystorePropertiesFile.inputStream().use { keystoreProperties.load(it) }
}

android {
    namespace = "homes.milky.vpn"
    compileSdk = 36
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    buildFeatures {
        buildConfig = true
        aidl = true
    }

    defaultConfig {
        applicationId = "vpn.milky.app"
        // API 23 — Android 6 devices. Reads the pinned value from
        // gradle.properties: the Flutter tooling migrator rewrites integer
        // literals here to flutter.minSdkVersion, which is hardcoded to 24.
        minSdk = project.property("flutter.minSdkVersion").toString().toInt()
        targetSdk = 36
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        // ABI set is driven by Flutter (--split-per-abi produces per-ABI APKs
        // so each install artifact stays under GitHub's 100 MB file cap).
        // Only ABIs shipped inside libv2ray.aar are built.
    }

    signingConfigs {
        if (hasReleaseKeystore) {
            create("release") {
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
            }
        }
    }

    buildTypes {
        release {
            // Debug signing is used ONLY when the owner has not provided key.properties.
            signingConfig = if (hasReleaseKeystore) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    packaging {
        jniLibs {
            // libgojni.so from AndroidLibXrayLite is 16 KB page aligned; keep it uncompressed
            // so the loader can mmap it directly.
            useLegacyPackaging = false
        }
    }

    bundle {
        language { enableSplit = false }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

flutter {
    source = "../.."
}

dependencies {
    // Xray-core Android binding (AndroidLibXrayLite, LGPL-3.0; Xray-core MPL-2.0).
    implementation(files("libs/libv2ray.aar"))
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

// crypto-kmp (vitorpamplona/crypto-kmp) is released on Nostr + Blossom: the Magpie settings plugin
// serves its group, trusting only the release key vitorpamplona.com names as `releases`, and
// gradle/magpie.lock pins that key and every resolved version's files. It also puts the publish plugin
// (com.vitorpamplona.magpie.publish) on the classpath, so build scripts apply that one by id alone.
plugins {
    id("com.vitorpamplona.magpie") version "0.2.0"
}

magpie {
    group("com.vitorpamplona.crypto")
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        // libschnorr256k1-kmp (the C library, for the comparison tests) comes from JitPack: only
        // that group, never asked of Maven Central. JitPack builds on Linux, so its JVM artifact
        // has the linux-x86_64 JNI library and no macOS one (the tests skip the C side there).
        exclusiveContent {
            forRepository { maven("https://jitpack.io") }
            filter { includeGroup("com.github.vitorpamplona.libschnorr256k1-kmp") }
        }
    }
}

rootProject.name = "libschnorr256k1-kotlin"
include(":schnorr256k1-kotlin")

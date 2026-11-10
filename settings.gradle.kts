pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
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

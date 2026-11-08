import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.SourcesJar
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.TestExecutable
import org.jetbrains.kotlin.konan.target.Family

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
}

// Every Kotlin/Native target except on JitPack, which builds JVM and Android only (see above).
val nativeTargets = providers.environmentVariable("JITPACK").orNull != "true"

kotlin {
    // A library: every public declaration is a choice, and the ABI dump in api/ records it,
    // so a breaking change shows up in review (and in a major version) instead of by accident.
    explicitApi()

    @OptIn(ExperimentalAbiValidation::class)
    abiValidation()

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    // JVM 21, as Quartz, the main consumer: a dependency can't need a newer JVM than the library
    // that uses it. 21 also gives Math.unsignedMultiplyHigh (Java 18+) on every supported JVM.
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }

    android {
        namespace = "com.vitorpamplona.schnorr256k1.kotlin"
        compileSdk =
            libs.versions.android.compileSdk
                .get()
                .toInt()
        minSdk =
            libs.versions.android.minSdk
                .get()
                .toInt()

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }

        withHostTest {}

        // commonTest again, on a device or emulator: ART, and the Android multiply-high paths
        // (Math.multiplyHigh from API 31, unsignedMultiplyHigh from 35, software below), which
        // the host tests' desktop JVM doesn't exercise. In the "test" tree, so it compiles
        // commonTest like the host tests do.
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    // JitPack (JITPACK=true) builds JVM and Android only: its Linux builders cannot build the Apple
    // cinterop, and its default image's glibc is too old for Kotlin/Native's clang (jitpack.yml).
    if (nativeTargets) {
        iosArm64()
        iosSimulatorArm64()
        macosArm64()
        linuxX64()
    }

    // Hardware 64x64->128 multiply-high on Kotlin/Native (MultiplyHigh.native.kt): C helpers in
    // src/nativeInterop/cinterop/mulhi.def, bound with @GCUnsafeCall. That annotation is a
    // Kotlin/Native internal API; its opt-in marker is not visible to source code, so it is
    // opted into here, for the per-target compilations and (below) the shared native source sets.
    targets
        .withType<KotlinNativeTarget>()
        .configureEach {
            compilations.getByName("main").cinterops.create("mulhi") {
                definitionFile.set(project.file("src/nativeInterop/cinterop/mulhi.def"))
            }
            compilations.configureEach {
                compileTaskProvider.configure {
                    compilerOptions.optIn.add("kotlin.native.internal.InternalForKotlinNative")
                }
            }
        }

    // Optimized linuxX64 test binary: the timing tests measure nothing on unoptimized code (~20x
    // slower). Apple test binaries stay unoptimized: an optimized link is a release-style LTO
    // build, which is slow on CI's macOS runners.
    targets
        .withType<KotlinNativeTarget>()
        .matching { it.konanTarget.family == Family.LINUX }
        .configureEach {
            binaries.withType<TestExecutable>().configureEach {
                optimized = true
                debuggable = false
            }
        }

    tasks.withType<Test>().configureEach {
        maxHeapSize = "2g"
    }

    sourceSets {
        commonMain {
            dependencies {
                // SHA-256 (BIP-340 tagged hashes)
                implementation(libs.crypto)
            }
        }

        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.kotlinx.coroutines.test)
            }
        }

        // JVM and Android share java.lang.ThreadLocal scratch buffers.
        val jvmAndroid =
            create("jvmAndroid") {
                dependsOn(commonMain.get())
            }

        jvmMain {
            dependsOn(jvmAndroid)
        }

        jvmTest {
            dependencies {
                // Cross-validation against libsecp256k1 (ACINQ) and libschnorr256k1 (C).
                implementation(libs.secp256k1.kmp)
                implementation(libs.secp256k1.kmp.jni.jvm)
                implementation(libs.schnorr256k1.kmp)
            }
        }

        androidMain {
            dependsOn(jvmAndroid)
        }

        getByName("androidHostTest") {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }

        getByName("androidDeviceTest") {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.androidx.test.runner)
                implementation(libs.androidx.test.junit)
            }
        }

        if (nativeTargets) {
            val nativeMain =
                create("nativeMain") {
                    dependsOn(commonMain.get())
                }

            val nativeTest =
                create("nativeTest") {
                    dependsOn(commonTest.get())
                }

            val appleMain =
                create("appleMain") {
                    dependsOn(nativeMain)
                }

            val appleTest =
                create("appleTest") {
                    dependsOn(nativeTest)
                }

            listOf("iosArm64", "iosSimulatorArm64", "macosArm64").forEach {
                getByName("${it}Main").dependsOn(appleMain)
                getByName("${it}Test").dependsOn(appleTest)
            }

            val linuxMain =
                create("linuxMain") {
                    dependsOn(nativeMain)
                }

            val linuxTest =
                create("linuxTest") {
                    dependsOn(nativeTest)
                }

            getByName("linuxX64Main").dependsOn(linuxMain)
            getByName("linuxX64Test").dependsOn(linuxTest)

            // MultiplyHigh.native.kt's @GCUnsafeCall, for the shared metadata compiles. Every source
            // set that depends on nativeMain must declare the same opt-in.
            listOf(
                nativeMain,
                appleMain,
                linuxMain,
                getByName("iosArm64Main"),
                getByName("iosSimulatorArm64Main"),
                getByName("macosArm64Main"),
                getByName("linuxX64Main"),
            ).forEach { it.languageSettings.optIn("kotlin.native.internal.InternalForKotlinNative") }
        }
    }
}

mavenPublishing {
    configure(
        KotlinMultiplatform(
            sourcesJar = SourcesJar.Sources(),
        ),
    )

    // groupId, artifactId, and version are configured via gradle.properties
    // (GROUP, POM_ARTIFACT_ID, VERSION_NAME) so CI can override VERSION_NAME
    // via ORG_GRADLE_PROJECT_VERSION_NAME without conflicting with a hardcoded value.

    publishToMavenCentral(automaticRelease = true)

    // Sign only when a key is configured: the release workflow passes one, while JitPack and
    // local publishToMavenLocal builds have none and would otherwise fail on the signing task.
    // Maven Central still rejects an unsigned upload, so a release can't slip out unsigned.
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }

    pom {
        name = "schnorr256k1-kotlin"
        description =
            "Pure-Kotlin BIP-340 Schnorr signatures, ECDH and key tweaks on secp256k1 for JVM, " +
            "Android, iOS, macOS and Linux"
        inceptionYear = "2026"
        url = "https://github.com/vitorpamplona/libschnorr256k1-kotlin/"
        licenses {
            license {
                name = "MIT License"
                url = "https://github.com/vitorpamplona/libschnorr256k1-kotlin/blob/main/LICENSE"
            }
        }
        developers {
            developer {
                id = "vitorpamplona"
                name = "Vitor Pamplona"
                url = "http://vitorpamplona.com"
                email = "vitor@vitorpamplona.com"
            }
        }
        scm {
            url = "https://github.com/vitorpamplona/libschnorr256k1-kotlin"
            connection = "https://github.com/vitorpamplona/libschnorr256k1-kotlin.git"
        }
    }
}

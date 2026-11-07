import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.SourcesJar
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.TestExecutable
import org.jetbrains.kotlin.konan.target.Family

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
}

kotlin {
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
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
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    iosArm64()
    iosSimulatorArm64()
    macosArm64()
    linuxX64()

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

mavenPublishing {
    configure(KotlinMultiplatform(sourcesJar = SourcesJar.Sources()))

    // groupId, artifactId and version come from gradle.properties (GROUP, POM_ARTIFACT_ID,
    // VERSION_NAME), so CI can override VERSION_NAME with ORG_GRADLE_PROJECT_VERSION_NAME.
    publishToMavenCentral(automaticRelease = true)
    signAllPublications()

    pom {
        name = "schnorr256k1-kotlin"
        description = "Pure-Kotlin BIP-340 Schnorr signatures on secp256k1 for Kotlin Multiplatform"
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
                url = "https://vitorpamplona.com"
            }
        }
        scm {
            url = "https://github.com/vitorpamplona/libschnorr256k1-kotlin/"
            connection = "scm:git:https://github.com/vitorpamplona/libschnorr256k1-kotlin.git"
            developerConnection = "scm:git:ssh://git@github.com/vitorpamplona/libschnorr256k1-kotlin.git"
        }
    }
}

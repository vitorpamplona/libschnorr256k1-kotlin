# schnorr256k1-kotlin

[![Last Version](https://img.shields.io/github/release/vitorpamplona/libschnorr256k1-kotlin.svg?maxAge=3600&label=Stable&labelColor=06599d&color=043b69)](https://github.com/vitorpamplona/libschnorr256k1-kotlin/releases/latest)
[![Maven Central](https://img.shields.io/maven-central/v/com.vitorpamplona.schnorr256k1/schnorr256k1-kotlin?label=Maven%20Central&labelColor=27303D&color=0877d2)](https://central.sonatype.com/artifact/com.vitorpamplona.schnorr256k1/schnorr256k1-kotlin)
[![CI](https://img.shields.io/github/actions/workflow/status/vitorpamplona/libschnorr256k1-kotlin/build.yml?labelColor=27303D)](https://github.com/vitorpamplona/libschnorr256k1-kotlin/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/github/license/vitorpamplona/libschnorr256k1-kotlin?labelColor=27303D&color=0877d2)](LICENSE)

BIP-340 Schnorr signatures and key operations on secp256k1, in pure Kotlin Multiplatform: no JNI,
no native library to ship, no WASM. It has the same API as
[libschnorr256k1-kmp](https://github.com/vitorpamplona/libschnorr256k1-kmp), the bindings to the C
library [libschnorr256k1](https://github.com/vitorpamplona/libschnorr256k1), so an app can switch
between the two by changing a dependency and an import.

The code started in [Quartz](https://github.com/vitorpamplona/quartz), Amethyst's Nostr library,
and is extracted here so other projects can use it and so its speed can be compared with the C
libraries in [libschnorr256k1-bench](https://github.com/vitorpamplona/libschnorr256k1-bench).

## Install

```kotlin
dependencies {
    implementation("com.vitorpamplona.schnorr256k1:schnorr256k1-kotlin:<version>")
}
```

## Platforms

| Platform | Notes |
|---|---|
| JVM (17+) | `Math.unsignedMultiplyHigh` for the 64x64 high product |
| Android (minSdk 26) | `Math.multiplyHigh` from API 31, `unsignedMultiplyHigh` from 35, a software multiply below |
| iOS, macOS (arm64), Linux (x86-64) | Kotlin/Native; the high product is one `umulh`/`mul` through a tiny inlined C helper (`src/nativeInterop/cinterop/mulhi.def`) |

## Use

```kotlin
import com.vitorpamplona.schnorr256k1.kotlin.Schnorr256k1

val pub = Schnorr256k1.pubkeyCreate(seckey)               // 65 bytes, 04 || x || y
val compressed = Schnorr256k1.pubkeyCompress(pub!!)       // 33 bytes
val xOnly = compressed!!.copyOfRange(1, 33)

val sig = Schnorr256k1.schnorrSign(msg, seckey, auxrand)  // any message length
val fast = Schnorr256k1.schnorrSignWithPubKey(msg, seckey, compressed, auxrand) // skips deriving the key
val ok = Schnorr256k1.schnorrVerify(sig!!, msg, xOnly)
val okFast = Schnorr256k1.schnorrVerifyFast(sig, msg, xOnly) // skips BIP-340's y-parity check of R

val shared = Schnorr256k1.ecdhXOnly(theirXOnly, seckey)   // NIP-04 / NIP-44
val tweaked = Schnorr256k1.privkeyTweakAdd(seckey, tweak)
val product = Schnorr256k1.pubkeyTweakMul(pub, tweak)
```

Invalid input returns `null` or `false`, as in libschnorr256k1-kmp. `schnorrSignWithPubKey` is not
in that API: it takes the 33-byte compressed key, whose prefix carries the y parity BIP-340 signing
needs, and so skips the generator multiplication that derives the key. `schnorrSignXOnly` cannot do
that (an x-only key has no parity) and costs the same as `schnorrSign`.

All functions are thread-safe: each thread works in its own scratch buffers, and the shared
caches publish their entries with release/acquire ordering.

## Known limits

- **Variable time.** Scalar multiplication (wNAF) and inversion (safegcd) take time that depends
  on their inputs, secrets included. Do not use it where a timing side channel matters.
  `docs/2026-11-07-secp256k1-constant-time-audit.md` lists what constant time would need.
- **Batch verification is not randomized yet.** `schnorrVerifyBatch` sums the signatures without
  BIP-340's random coefficients, so invalid signatures crafted to cancel each other pass (from two
  valid signatures by one key, `s1 + d` and `s2 - d`). It cannot forge a signature for new
  content, but use `schnorrVerify` where every signature must be valid on its own.

## Differences from libschnorr256k1-kmp found so far

The JVM tests call both libraries side by side (`Schnorr256k1ApiParityTest`) and found two bugs
in libschnorr256k1 (C), both reproduced against libsecp256k1:

- `schnorrSignXOnly` (`secp256k1c_schnorr_sign_xonly`) assumes the key has even y, and returns an
  invalid signature for the half of all keys whose public key has odd y.
- `pubkeyTweakMul`'s scalar multiplication shares an x-keyed table cache with verification. After
  a tweak-mul of an odd-y key, verify rejects valid signatures for that key's x-only form; after a
  verify, the tweak-mul of the odd-y key returns the negated point.

## Build and test

```bash
./gradlew installGitHook                          # pre-commit (spotless) and pre-push (the CI checks)
./gradlew :schnorr256k1-kotlin:jvmTest            # also cross-validates against libsecp256k1 and libschnorr256k1
./gradlew :schnorr256k1-kotlin:linuxX64Test       # macOS: macosArm64Test, iosSimulatorArm64Test
./gradlew :schnorr256k1-kotlin:checkKotlinAbi     # the public API matches schnorr256k1-kotlin/api/
./gradlew spotlessApply
```

Releasing: bump `VERSION_NAME` in `gradle.properties` and push a `v<version>` tag
(`.github/workflows/create-release.yml`).

## License

MIT. `SafeGcd.kt` is a port of libsecp256k1's `modinv64_var` (MIT, attributed in the file).

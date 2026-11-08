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

// Key and point arithmetic, as libsecp256k1's ec_pubkey_* functions (BIP-341 tweaks, Cashu's BDHKE)
val full = Schnorr256k1.pubkeyParse(compressed)           // 65 bytes; null if not on the curve
val sum = Schnorr256k1.pubkeyCombine(listOf(pub, other))  // P + Q, 65 bytes
val minusP = Schnorr256k1.pubkeyNegate(compressed)        // -P, in the input's format
val tweakedPub = Schnorr256k1.pubkeyTweakAdd(compressed, tweak) // P + tweak·G
val minusD = Schnorr256k1.privkeyNegate(seckey)           // n - d
```

Invalid input returns `null` or `false`, as in libschnorr256k1-kmp. The point arithmetic and
`schnorrSignWithPubKey` are not in that API. Key parsing follows libsecp256k1: compressed,
uncompressed and hybrid (`06`/`07`) keys, with canonical coordinates. `schnorrSignWithPubKey` it takes the 33-byte compressed key, whose prefix carries the y parity BIP-340 signing
needs, and so skips the generator multiplication that derives the key. `schnorrSignXOnly` cannot do
that (an x-only key has no parity) and costs the same as `schnorrSign`.

All functions are thread-safe: each thread works in its own scratch buffers, and the shared
caches publish their entries with release/acquire ordering.

## Known limits

- **Variable time.** Scalar multiplication (wNAF) and inversion (safegcd) take time that depends
  on their inputs, secrets included. Do not use it where a timing side channel matters.
  `docs/2026-11-07-secp256k1-constant-time-audit.md` lists what constant time would need.
- **Batch verification costs about 60% of a single verify per signature.** `schnorrVerifyBatch`
  is BIP-340's batch verification: each signature gets a 128-bit weight derived from a hash of the
  whole batch, so invalid signatures cannot be made to cancel. The weights cost a 128-bit scalar
  multiplication per signature. Until 2026-11-07 the batch summed the signatures without weights,
  and two invalid signatures crafted to cancel (`s1 + d`, `s2 - d`) passed.

## Fixed before 1.0.0

- **Square roots of small values.** The field multiply leaves results below 2²⁵⁶, not below p, and
  the square root compared `out²` with its input without reducing it. For an input below
  2²⁵⁶ − p (x³ + 7 for a small x) it rejected valid roots, so points such as x = 1 failed to
  parse or lift. Affine coordinates and the equality tests of point addition are now reduced too.
  Random inputs reach none of these with any real probability (about 2⁻²²⁴); chosen ones did.
- **`pubkeyCompress` validates its input**, as libsecp256k1 does; it used to re-encode any 65 or
  33 bytes with the right prefix, on the curve or not.
- **Batch verification is weighted** (BIP-340), so invalid signatures cannot cancel.

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

# libschnorr256k1-kotlin

BIP-340 Schnorr signatures, x-only ECDH and key tweaks on secp256k1, in pure Kotlin
Multiplatform, with the same public API as
[libschnorr256k1-kmp](https://github.com/vitorpamplona/libschnorr256k1-kmp)'s `Schnorr256k1` (the
bindings to the C library [libschnorr256k1](https://github.com/vitorpamplona/libschnorr256k1)).
Published to Maven Central as `com.vitorpamplona.schnorr256k1:schnorr256k1-kotlin`. The code
started in [Quartz](https://github.com/vitorpamplona/quartz) (`com.vitorpamplona.quartz.utils.secp256k1`)
and moved here so other projects can use it without a Nostr library, and so
[libschnorr256k1-bench](https://github.com/vitorpamplona/libschnorr256k1-bench) can compare it with
the C libraries.

## Layout

- `schnorr256k1-kotlin/` — the library, in `com.vitorpamplona.schnorr256k1.kotlin`.
  `Schnorr256k1.kt` is the whole public API (a facade); everything else is `internal`:
  `Secp256k1` (the operations), `ECPoint`, `FieldP`, `ScalarN`, `U256`, `Glv`, `KeyCodec`,
  `SafeGcd`.
- Source sets: `jvmAndroid` (java.lang.ThreadLocal scratch, shared by JVM and Android), `jvmMain`
  (`Math.unsignedMultiplyHigh`, `Long.compareUnsigned`), `androidMain` (API-gated
  `Math.multiplyHigh`/`unsignedMultiplyHigh`, a software multiply below API 31, the xor-trick
  compare), and `nativeMain` above `appleMain` and `linuxMain` (per-thread scratch through a
  `@ThreadLocal` array, and the hardware multiply-high).
- `schnorr256k1-kotlin/src/nativeInterop/cinterop/mulhi.def` — two C helpers for the 64x64
  high product, bound with `@GCUnsafeCall` so the call skips cinterop's GC state switch and LLVM
  inlines the body into one `mul`/`umulh`. Their symbols are `schnorr256k1kt_*` so they cannot
  clash with a copy linked into the same binary (Quartz has `quartz_*`). The `compilerOpts`
  CPU flags must match Kotlin/Native's target CPUs, or LLVM refuses to inline.
- `schnorr256k1-kotlin/api/` — the public ABI dumps (`checkKotlinAbi`).
- `docs/` — design notes and measurements (operation counts against libsecp256k1, the JVM
  field-multiply experiments, the constant-time audit).

## Rules

- **Performance is the goal, and every claim is measured.** Benchmark before and after a change
  on the platform it affects. On HotSpot the right idiom differs per routine: `sqrWide` wants
  the xor-trick carry and `mulWide` wants `Long.compareUnsigned`
  (`docs/2026-11-07-secp256k1-jvm-field-mul-experiments.md`). Comparisons with other libraries
  belong in libschnorr256k1-bench.
- **Hot paths do not allocate.** `Secp256k1AllocationTest` fails if verify, `FieldP.mul` or
  `FieldP.inv` allocate. ART has no escape analysis: return flags as `Int` bits, not objects.
- **Scratch buffers are per thread** (`ScratchLocal`), and a shared cache publishes its entries
  through `AtomicArray`. A value that must survive a point operation never lives in point
  scratch (`toAffine` writes `zInv`): that is how the signing bug fixed on 2026-11-07 happened.
- **A per-x cache must only ever see one of P and -P.** Verify uses the even-y lift of an x-only
  key; tweak-mul and ECDH take any point. `MixedParityKeyTest` guards this (libschnorr256k1 got it
  wrong).
- **Correctness is checked against other implementations:** `Secp256k1CrossValidationTest`
  (libsecp256k1 via ACINQ, and libschnorr256k1), `Schnorr256k1ApiParityTest` (call-for-call API
  parity with libschnorr256k1-kmp, refereed by libsecp256k1 where the C library is wrong),
  BIP-340 vectors in `SchnorrTest`, `SafeGcdTest` (against Fermat), `SignEntryPointsTest`.
- **Variable time.** Scalar multiplication and inversion take time that depends on their inputs,
  secrets included; constant time is not a goal for now (`docs/...constant-time-audit.md`). Say
  so in any API doc where it matters.
- **Dependencies:** crypto-kmp (SHA-256) and the Kotlin stdlib only. ACINQ's secp256k1-kmp and
  libschnorr256k1-kmp are test dependencies. A new dependency needs its license checked against
  its actual `LICENSE` file first, and a very good reason.
- Code ported from elsewhere keeps its attribution (`SafeGcd.kt` is libsecp256k1's
  `modinv64_var`, MIT).
- `commonMain` and `commonTest` stay free of JVM-only APIs: the Linux and Apple targets compile
  them as common code. In tests use `assertTrue`, not `assert`.
- Apple code compiles on Linux as metadata (`:schnorr256k1-kotlin:compileAppleMainKotlinMetadata`)
  but its binaries (and the cinterop) build only on macOS: CI's `test-apple` job is where the
  Apple targets run, and releases publish from macOS.
- Android's multiply-high paths run only on a device: CI's `test-android` job runs commonTest on
  emulators at API 26, 31 and 35, one per path.
- JVM target is 21: Quartz targets 21, and a dependency can't need a newer JVM than its user.
- Before pushing: `./gradlew spotlessApply`, then
  `./gradlew :schnorr256k1-kotlin:checkKotlinAbi :schnorr256k1-kotlin:jvmTest :schnorr256k1-kotlin:testAndroidHostTest :schnorr256k1-kotlin:linuxX64Test :schnorr256k1-kotlin:compileCommonMainKotlinMetadata :schnorr256k1-kotlin:compileNativeMainKotlinMetadata :schnorr256k1-kotlin:compileAppleMainKotlinMetadata`
  (the pre-push hook runs these; `./gradlew installGitHook` installs it).
- **Explicit API mode** is on: every public declaration says `public`, and
  `schnorr256k1-kotlin/api/` records the public ABI. A deliberate API change runs
  `./gradlew :schnorr256k1-kotlin:updateKotlinAbi` (it needs the Android SDK; on Linux the Apple
  dumps are inferred from linuxX64) and commits the new dump; anything that should not be API is
  `internal`.
- **Same behaviour as libschnorr256k1-kmp** for the same call: invalid input returns `null` or
  `false`, never throws. Where the C library is wrong, match libsecp256k1 and record the
  difference in `README.md`.
- Releases follow semantic versioning: a breaking change to the public API bumps the major
  version.
- Commits: conventional commits (`feat:`, `fix:`, `perf:`, …). Never `--no-verify`.

## Remotes and pull requests

The repo is on GitHub, `github.com/vitorpamplona/libschnorr256k1-kotlin`, which holds the canonical
`main`. It is not announced as a NIP-34 repository on nostr yet; once it is (`ngit init`), PRs can
also go out as nostr proposals, like crypto-kmp's and Quartz's. Remote names vary per clone, so
identify them by URL. Open a PR only when the human you work for asks, and before opening, revising
or merging one, use the `ngit-pr` skill.

## Releasing

Bump `VERSION_NAME` in `gradle.properties`, then push a `v<version>` tag. The
`create-release.yml` workflow runs the Apple tests on macOS, then tests, publishes to Maven
Central (from macOS, because of the cinterop) and opens the GitHub release. It needs the same
signing secrets as crypto-kmp and quic-kmp (`SONATYPE_USERNAME`, `SONATYPE_PASSWORD`,
`SIGNING_PRIVATE_KEY`, `SIGNING_PASSWORD`).

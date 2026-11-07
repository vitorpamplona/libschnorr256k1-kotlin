# schnorr256k1-kotlin

Pure-Kotlin Multiplatform BIP-340 Schnorr on secp256k1, with the same public API as
[libschnorr256k1-kmp](https://github.com/vitorpamplona/libschnorr256k1-kmp)'s `Schnorr256k1`. See
`README.md`. The code came from Quartz (`com.vitorpamplona.quartz.utils.secp256k1`).

## Layout

- `schnorr256k1-kotlin/`: the library module.
  - `src/commonMain/.../schnorr256k1/kotlin/Schnorr256k1.kt`: the public API (a facade).
    Everything else is `internal`: `Secp256k1` (the operations), `ECPoint`, `FieldP`, `ScalarN`,
    `U256`, `Glv`, `KeyCodec`, `SafeGcd`.
  - Source sets: `commonMain`; `jvmAndroid` (shared by `jvmMain` and `androidMain`); `nativeMain`
    above `appleMain` and `linuxMain`. Platform files hold the multiply-high and unsigned-compare
    intrinsics and the per-thread scratch.
  - `src/nativeInterop/cinterop/mulhi.def`: the C multiply-high helpers, bound with
    `@GCUnsafeCall`. Their symbols are `schnorr256k1kt_*` so they cannot clash with a copy linked
    into the same binary (Quartz has `quartz_*`).
- `docs/`: design notes and measurements.

## Rules

- **Performance is the goal, and every claim is measured.** Benchmark before and after a change
  on the platform it affects; on HotSpot the right idiom differs per routine (see
  `docs/2026-11-07-secp256k1-jvm-field-mul-experiments.md`: `sqrWide` wants the xor carry,
  `mulWide` wants `Long.compareUnsigned`). Cross-library benchmarks live in libschnorr256k1-bench.
- **Hot paths do not allocate.** `Secp256k1AllocationTest` fails if verify, `FieldP.mul` or
  `FieldP.inv` allocate. ART has no escape analysis: return flags as `Int` bits, not objects.
- **Scratch buffers are per thread** (`ScratchLocal`) and a shared cache publishes entries through
  `AtomicArray`. A value that must survive a point operation never lives in point scratch
  (`toAffine` writes `zInv`): that is how the signing bug fixed on 2026-11-07 happened.
- **A per-x cache must only ever see one of P and -P.** Verify uses the even-y lift of an x-only
  key; tweak-mul and ECDH take any point. `MixedParityKeyTest` guards this.
- **Correctness is checked against other implementations**: `Secp256k1CrossValidationTest`
  (libsecp256k1 via ACINQ, libschnorr256k1), `Schnorr256k1ApiParityTest` (call-for-call API
  parity), BIP-340 vectors in `SchnorrTest`, `SafeGcdTest` (against Fermat).
- `commonMain` and `commonTest` stay free of JVM-only APIs.
- Commits: conventional commits (`feat:`, `fix:`, `perf:`, ...).

## Build and test

```bash
./gradlew :schnorr256k1-kotlin:jvmTest
./gradlew :schnorr256k1-kotlin:linuxX64Test      # macOS: macosArm64Test / iosSimulatorArm64Test
./gradlew spotlessApply
```

## Remotes and pull requests

The repo is on GitHub, `github.com/vitorpamplona/libschnorr256k1-kotlin`. Open a PR only when the
human you work for asks.

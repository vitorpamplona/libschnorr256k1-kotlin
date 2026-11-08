/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
@file:OptIn(ExperimentalAtomicApi::class)

package com.vitorpamplona.schnorr256k1.kotlin

import com.vitorpamplona.crypto.sha2.sha256
import com.vitorpamplona.crypto.sha2.sha256Into
import com.vitorpamplona.schnorr256k1.kotlin.Secp256k1.ecdhXOnly
import com.vitorpamplona.schnorr256k1.kotlin.Secp256k1.privKeyTweakAdd
import com.vitorpamplona.schnorr256k1.kotlin.Secp256k1.pubKeyCompress
import com.vitorpamplona.schnorr256k1.kotlin.Secp256k1.pubKeyTweakMul
import com.vitorpamplona.schnorr256k1.kotlin.Secp256k1.pubkeyCreate
import com.vitorpamplona.schnorr256k1.kotlin.Secp256k1.secKeyVerify
import com.vitorpamplona.schnorr256k1.kotlin.Secp256k1.signSchnorr
import com.vitorpamplona.schnorr256k1.kotlin.Secp256k1.signSchnorrWithPubKey
import com.vitorpamplona.schnorr256k1.kotlin.Secp256k1.verifySchnorr
import kotlin.concurrent.atomics.AtomicArray
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Pure Kotlin implementation of secp256k1 elliptic curve operations for Nostr.
 *
 * Portable KMP implementation that runs on all Kotlin targets (JVM, Android, iOS,
 * Linux) without requiring platform-specific native libraries.
 *
 * Provides only the operations used by Nostr:
 * - [pubkeyCreate] / [pubKeyCompress]: Key generation
 * - [secKeyVerify]: Key validation
 * - [signSchnorr] / [signSchnorrWithPubKey] / [verifySchnorr]: BIP-340 Schnorr (NIP-01)
 * - [privKeyTweakAdd]: BIP-32 key derivation (NIP-06)
 * - [pubKeyTweakMul] / [ecdhXOnly]: ECDH shared secrets (NIP-04, NIP-44)
 *
 * Performance on JVM (vs native C/JNI secp256k1, 2000+ warmup, 3000-5000 iterations):
 *   verify        ~15,000 ops/s  (1.7× native, with pubkey cache)
 *   sign          ~18,000 ops/s  (1.5× native)
 *   sign(cached)  ~28,000 ops/s  (0.9× — FASTER than native)
 *   pubCreate     ~38,000 ops/s  (1.3× native)
 *   ECDH          ~14,000 ops/s  (2.0× native)
 *
 * Key optimizations:
 *   - Unrolled 4×64-bit field arithmetic (mulWide, sqrWide, addTo, subTo)
 *   - GLV endomorphism + wNAF + comb method + Strauss/Shamir
 *   - Ping-pong point buffers (eliminates copyFrom in scalar mul loops)
 *   - Pre-allocated ThreadLocal scratch (eliminates ~130 allocs/operation)
 *   - Pubkey decompression cache (skips sqrt for repeated pubkeys)
 *   - P-side wNAF table cache (skips table build for repeated pubkeys)
 *   - Direct unsigned multiplyHigh fallback (faster on Android < API 31)
 *
 * Remaining gap vs C libsecp256k1:
 *   - No lazy reduction (4×64 limbs fully packed; C's 5×52 have 12-bit headroom)
 *   - Fermat inversion instead of safegcd (safegcd slower on JVM)
 *   - WINDOW_G=12 vs 15 (JVM heap tables cause cache pressure at w=15)
 *   - No constant-time guarantees (not needed for Nostr)
 */
internal object Secp256k1 {
    // ==================== Cached BIP-340 tag hash prefixes ====================
    //
    // BIP-340 uses "tagged hashes": SHA256(SHA256(tag) || SHA256(tag) || message).
    // The tag prefixes SHA256(tag) || SHA256(tag) are constant per tag string.
    // We precompute them once to save 2 SHA256 calls per sign/verify operation.

    private val CHALLENGE_PREFIX: ByteArray = sha256("BIP0340/challenge".encodeToByteArray()).let { it + it }
    private val AUX_PREFIX: ByteArray = sha256("BIP0340/aux".encodeToByteArray()).let { it + it }
    private val NONCE_PREFIX: ByteArray = sha256("BIP0340/nonce".encodeToByteArray()).let { it + it }

    // ==================== Pubkey decompression cache ====================
    //
    // liftX (square root on secp256k1) costs ~280 field ops per call. In Nostr,
    // the same pubkeys are verified repeatedly (every event from the same author).
    // This cache maps x-only pubkey bytes → decompressed (x, y) coordinates,
    // saving the sqrt for repeated pubkeys (~13% of verify cost per cache hit).
    //
    // Simple fixed-size direct-mapped cache (no LRU overhead). Size must be power of 2.
    // 1024 entries covers most follow lists (~1000 users) with few collisions.
    // Memory: 1024 × ~96 bytes = ~96KB.
    private const val PUBKEY_CACHE_SIZE = 1024 // power of 2
    private const val PUBKEY_CACHE_MASK = PUBKEY_CACHE_SIZE - 1

    private class CachedPubkey(
        val keyBytes: ByteArray, // 32-byte x-only pubkey (for equality check)
        val px: Fe4, // decompressed x (4 limbs)
        val py: Fe4, // decompressed y (4 limbs)
    )

    // Shared by all threads; AtomicArray for safe publication of entries (see ECPoint.pTableCache).
    private val pubkeyCache = AtomicArray(arrayOfNulls<CachedPubkey>(PUBKEY_CACHE_SIZE))

    /**
     * liftX with caching. Returns true and fills outX/outY if the pubkey is valid.
     * On cache hit, copies the cached coordinates (2 array copies, ~trivial).
     * On cache miss, computes sqrt and stores the result.
     */
    private fun liftXCached(
        outX: Fe4,
        outY: Fe4,
        pub: ByteArray,
    ): Boolean {
        // Hash the pubkey bytes to a cache slot (use first 4 bytes as index)
        val slot =
            (
                (pub[0].toInt() and 0xFF) or
                    ((pub[1].toInt() and 0xFF) shl 8)
            ) and PUBKEY_CACHE_MASK

        val cached = pubkeyCache.loadAt(slot)
        if (cached != null && cached.keyBytes.contentEquals(pub)) {
            // Cache hit — copy pre-computed coordinates
            outX.copyFrom(cached.px)
            outY.copyFrom(cached.py)
            return true
        }

        // Cache miss — compute sqrt and store
        if (!KeyCodec.liftX(outX, outY, U256.fromBytes(pub))) return false

        pubkeyCache.storeAt(slot, CachedPubkey(pub.copyOf(), outX.copyOf(), outY.copyOf()))
        return true
    }

    // ==================== Key operations ====================

    /** Create a 65-byte uncompressed public key (04 || x || y) from a 32-byte secret key. */
    fun pubkeyCreate(seckey: ByteArray): ByteArray {
        require(seckey.size == 32)
        val sc = ECPoint.getScratch()
        val scalar = sc.scalarTmp1
        U256.fromBytesInto(scalar, seckey, 0)
        require(ScalarN.isValid(scalar))
        ECPoint.mulG(sc.entryResult, scalar, sc)
        check(ECPoint.toAffine(sc.entryResult, sc.entryPx, sc.entryPy, sc))
        return KeyCodec.serializeUncompressed(sc.entryPx, sc.entryPy)
    }

    /**
     * 33-byte compressed form of a 33- or 65-byte (or hybrid) public key. Validates it, as
     * libsecp256k1 does: a key that is not on the curve fails instead of being re-encoded.
     */
    fun pubKeyCompress(pubkey: ByteArray): ByteArray {
        val x = Fe4()
        val y = Fe4()
        require(KeyCodec.parsePublicKey(pubkey, x, y)) { "Invalid public key: size=${pubkey.size}" }
        return KeyCodec.serializeCompressed(x, y)
    }

    /**
     * Verify that a byte array is a valid secret key (32 bytes, 0 < value < n).
     * Operates directly on bytes without converting to limbs — avoids LongArray allocation.
     */
    fun secKeyVerify(seckey: ByteArray): Boolean {
        if (seckey.size != 32) return false
        // Check not zero (any non-zero byte means non-zero)
        var nonZero = 0
        for (b in seckey) nonZero = nonZero or b.toInt()
        if (nonZero == 0) return false
        // Check < n by comparing big-endian bytes against n
        // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        for (i in 0 until 32) {
            val si = seckey[i].toInt() and 0xFF
            val ni = N_BYTES[i].toInt() and 0xFF
            if (si < ni) return true // definitely less
            if (si > ni) return false // definitely greater
        }
        return false // equal to n → invalid
    }

    // n as big-endian bytes for direct comparison
    private val N_BYTES =
        byteArrayOf(
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFE.toByte(),
            0xBA.toByte(),
            0xAE.toByte(),
            0xDC.toByte(),
            0xE6.toByte(),
            0xAF.toByte(),
            0x48.toByte(),
            0xA0.toByte(),
            0x3B.toByte(),
            0xBF.toByte(),
            0xD2.toByte(),
            0x5E.toByte(),
            0x8C.toByte(),
            0xD0.toByte(),
            0x36.toByte(),
            0x41.toByte(),
            0x41.toByte(),
        )

    // ==================== BIP-340 Schnorr Signatures ====================

    /**
     * Create a BIP-340 Schnorr signature.
     *
     * This convenience overload derives the public key from the secret key.
     * For repeated signing with the same key, prefer [signSchnorrWithPubKey]
     * to avoid redundant G multiplication.
     */
    fun signSchnorr(
        data: ByteArray,
        seckey: ByteArray,
        auxrand: ByteArray?,
    ): ByteArray {
        require(seckey.size == 32)
        // d0 must survive through mulG (which destroys splitK*) and signSchnorrInternal
        // (which uses scalarTmp*). The allocation is negligible vs mulG cost (~100μs).
        val d0 = U256.fromBytes(seckey)
        require(ScalarN.isValid(d0))
        val sc = ECPoint.getScratch()
        ECPoint.mulG(sc.entryResult, d0, sc)
        check(ECPoint.toAffine(sc.entryResult, sc.entryPx, sc.entryPy, sc))

        // Allocate xOnlyPub — signSchnorrInternal reuses bytesTmp1/2 internally.
        // This 32-byte allocation is negligible next to the mulG cost (~100μs).
        val xOnlyPub = U256.toBytes(sc.entryPx)
        return signSchnorrInternal(data, d0, xOnlyPub, KeyCodec.hasEvenY(sc.entryPy), auxrand)
    }

    /**
     * Create a BIP-340 Schnorr signature with a pre-computed compressed public key.
     *
     * This is the fast path — skips the expensive G multiplication for public key
     * derivation. The 33-byte compressed key provides both the x-coordinate (for the
     * BIP-340 tagged hash) and the y-parity (02=even, 03=odd, needed to determine
     * whether to negate the secret key).
     *
     * The C library's signing function similarly takes a pre-computed keypair.
     *
     * @param data Message bytes (any length)
     * @param seckey 32-byte secret key
     * @param compressedPub 33-byte compressed public key (02/03 || x)
     * @param auxrand Optional 32-byte auxiliary randomness (null for deterministic)
     */
    fun signSchnorrWithPubKey(
        data: ByteArray,
        seckey: ByteArray,
        compressedPub: ByteArray,
        auxrand: ByteArray?,
    ): ByteArray {
        require(seckey.size == 32 && compressedPub.size == 33)
        require(compressedPub[0] == 0x02.toByte() || compressedPub[0] == 0x03.toByte())
        // Not a scratch buffer: signSchnorrInternal's R = k·G and its affine conversion reuse the
        // point scratch (toAffine writes sc.zInv), and d must survive until s = k + e·d.
        val d0 = U256.fromBytes(seckey)
        require(ScalarN.isValid(d0))
        val hasEvenY = compressedPub[0] == 0x02.toByte()
        val xOnlyPub = compressedPub.copyOfRange(1, 33)
        return signSchnorrInternal(data, d0, xOnlyPub, hasEvenY, auxrand)
    }

    /**
     * Signing with the 32-byte x-only public key already known.
     *
     * Costs the same as [signSchnorr]: BIP-340 signs with d or n - d depending on the parity of
     * y in d·G, and an x-only key does not carry that parity, so it is derived here. (An earlier
     * version assumed even y, and produced invalid signatures for half of all keys.) The fast
     * path is [signSchnorrWithPubKey], whose 33-byte compressed key carries the parity.
     *
     * Fails (IllegalArgumentException) if [xOnlyPub] is not the x-only key of [seckey].
     */
    fun signSchnorrWithXOnlyPubKey(
        data: ByteArray,
        seckey: ByteArray,
        xOnlyPub: ByteArray,
        auxrand: ByteArray?,
    ): ByteArray {
        require(seckey.size == 32 && xOnlyPub.size == 32)
        val d0 = U256.fromBytes(seckey)
        require(ScalarN.isValid(d0))
        val sc = ECPoint.getScratch()
        ECPoint.mulG(sc.entryResult, d0, sc)
        check(ECPoint.toAffine(sc.entryResult, sc.entryPx, sc.entryPy, sc))
        require(U256.toBytes(sc.entryPx).contentEquals(xOnlyPub)) { "xOnlyPub is not the public key of seckey" }
        return signSchnorrInternal(data, d0, xOnlyPub, KeyCodec.hasEvenY(sc.entryPy), auxrand)
    }

    /**
     * Internal signing implementation shared by both public overloads.
     * Performs: nonce derivation → R = k·G → challenge → s = k + e·d.
     * Does NOT re-derive the public key or self-verify (matching the C library).
     */
    private fun signSchnorrInternal(
        data: ByteArray,
        d0: Fe4,
        pBytes: ByteArray,
        pubKeyHasEvenY: Boolean,
        auxrand: ByteArray?,
    ): ByteArray {
        val sc = ECPoint.getScratch()

        val d: Fe4 =
            if (pubKeyHasEvenY) {
                d0
            } else {
                ScalarN.negTo(sc.entryTmp, d0)
                sc.entryTmp
            }
        // Serialize d into scratch byte buffer (avoids U256.toBytes allocation)
        val dBytes = sc.bytesTmp1
        U256.toBytesInto(d, dBytes, 0)

        val tBytes: ByteArray
        if (auxrand != null) {
            require(auxrand.size == 32)
            // Build AUX_PREFIX + auxrand in scratch hashBuf (avoids concatenation alloc)
            AUX_PREFIX.copyInto(sc.hashBuf, 0, 0, 64)
            auxrand.copyInto(sc.hashBuf, 64, 0, 32)
            sha256Into(sc.bytesTmp2, sc.hashBuf, 96)
            // XOR d with auxHash — reuse limb scratch
            U256.fromBytesInto(sc.scalarTmp1, dBytes, 0)
            U256.fromBytesInto(sc.scalarTmp2, sc.bytesTmp2, 0)
            U256.xorTo(sc.scalarTmp3, sc.scalarTmp1, sc.scalarTmp2)
            tBytes = sc.bytesTmp2 // reuse bytesTmp2 for tBytes
            U256.toBytesInto(sc.scalarTmp3, tBytes, 0)
        } else {
            tBytes = dBytes
        }

        // Build nonce input. Reuse hashBuf if it fits.
        val nonceLen = 64 + 32 + 32 + data.size
        val nonceInput = if (nonceLen <= sc.hashBuf.size) sc.hashBuf else ByteArray(nonceLen)
        NONCE_PREFIX.copyInto(nonceInput, 0, 0, 64)
        tBytes.copyInto(nonceInput, 64, 0, 32)
        pBytes.copyInto(nonceInput, 96, 0, 32)
        data.copyInto(nonceInput, 128, 0, data.size)
        sha256Into(sc.bytesTmp2, nonceInput, nonceLen) // rand → bytesTmp2
        U256.fromBytesInto(sc.scalarTmp1, sc.bytesTmp2, 0)
        ScalarN.reduceTo(sc.scalarTmp1, sc.scalarTmp1)
        val k0 = sc.scalarTmp1
        // BIP-340 step "Fail if k' = 0". Probability ~2^-256, unreachable in
        // practice but the spec requires refusal. `check` here (vs the prior
        // `require`) communicates it as an internal invariant rather than an
        // argument error, matching the semantics of the C side returning 0.
        check(!k0.isZero()) { "BIP-340 nonce derived to 0 — refuse to sign" }

        // R = k0·G
        ECPoint.mulG(sc.entryResult, k0, sc)
        val rx = sc.entryPx
        val ry = sc.entryPy
        check(ECPoint.toAffine(sc.entryResult, rx, ry, sc))

        val k: Fe4 =
            if (KeyCodec.hasEvenY(ry)) {
                k0
            } else {
                ScalarN.negTo(sc.scalarTmp2, k0)
                sc.scalarTmp2
            }

        // Challenge: e = H(R || P || msg) — reuse hashBuf
        val chalLen = 64 + 32 + 32 + data.size
        val chalInput = if (chalLen <= sc.hashBuf.size) sc.hashBuf else ByteArray(chalLen)
        CHALLENGE_PREFIX.copyInto(chalInput, 0, 0, 64)
        U256.toBytesInto(rx, chalInput, 64)
        pBytes.copyInto(chalInput, 96, 0, 32)
        data.copyInto(chalInput, 128, 0, data.size)
        sha256Into(sc.bytesTmp1, chalInput, chalLen) // eHash → bytesTmp1
        U256.fromBytesInto(sc.scalarTmp3, sc.bytesTmp1, 0)
        ScalarN.reduceTo(sc.scalarTmp3, sc.scalarTmp3)
        val e = sc.scalarTmp3

        // s = k + e·d mod n
        // Note: d may alias sc.entryTmp (when !pubKeyHasEvenY), so use splitK1 for mulTo output.
        ScalarN.mulTo(sc.splitK1, e, d, sc.splitWide) // e·d → splitK1
        ScalarN.addTo(sc.entryTmp2, k, sc.splitK1) // k + e·d → entryTmp2

        // Build output signature (the only required allocation)
        val sig = ByteArray(64)
        U256.toBytesInto(rx, sig, 0)
        U256.toBytesInto(sc.entryTmp2, sig, 32)
        return sig
    }

    /**
     * Verify a BIP-340 Schnorr signature.
     *
     * This is the performance-critical operation for a Nostr client — every received
     * event must be verified. The algorithm:
     * 1. Decompress public key P from x-only representation
     * 2. Parse r (x-coordinate of R) and s from signature
     * 3. Compute challenge e = H(r || P || msg)
     * 4. Compute R' = s·G - e·P using Shamir's trick (single combined scalar mul)
     * 5. Verify R' is not infinity, has even y, and x(R') = r
     *
     * @param signature 64-byte signature (R.x || s)
     * @param data Message bytes (any length)
     * @param pub 32-byte x-only public key
     */
    fun verifySchnorr(
        signature: ByteArray,
        data: ByteArray,
        pub: ByteArray,
    ): Boolean {
        if (signature.size != 64 || pub.size != 32) return false
        val sc = ECPoint.getScratch()
        if (!verifySchnorrCore(signature, data, pub, sc)) return false

        // x matches — check y-parity (requires inversion, ~270 field ops)
        FieldP.inv(sc.zInv, sc.entryResult.z)
        FieldP.sqr(sc.zInv2, sc.zInv)
        FieldP.mul(sc.zInv3, sc.zInv2, sc.zInv)
        FieldP.mul(sc.entryPy, sc.entryResult.y, sc.zInv3)
        return KeyCodec.hasEvenY(sc.entryPy)
    }

    /**
     * Fast Nostr event signature verification — skips the BIP-340 y-parity check.
     *
     * BIP-340 requires R.y to be even. The full [verifySchnorr] enforces this with a
     * field inversion (~270 field ops, ~14% of verify cost). This variant skips that
     * check, verifying only that R.x matches the signature's r value.
     *
     * WHY THIS IS SAFE FOR NOSTR:
     * For a given x-coordinate on secp256k1, there are exactly two curve points:
     * (x, y_even) and (x, y_odd). A signature that produces the correct x but wrong
     * y-parity would require solving the discrete log problem — computationally
     * equivalent to forging the signature entirely. The y-parity check is
     * defense-in-depth, not a distinct security boundary.
     *
     * DO NOT use this for Bitcoin transaction validation or any financial protocol
     * where strict BIP-340 compliance is required.
     *
     * @param signature 64-byte signature (R.x || s)
     * @param data Message bytes (any length)
     * @param pub 32-byte x-only public key
     */
    fun verifySchnorrFast(
        signature: ByteArray,
        data: ByteArray,
        pub: ByteArray,
    ): Boolean {
        if (signature.size != 64 || pub.size != 32) return false
        val sc = ECPoint.getScratch()
        return verifySchnorrCore(signature, data, pub, sc)
    }

    /**
     * Shared core of Schnorr verification: validates inputs, computes
     * Q = s·G + (-e)·P via Shamir's trick, and checks that Q.x matches
     * the signature's r value in Jacobian coordinates (no inversion).
     *
     * Leaves the Jacobian result point in [sc].entryResult for callers
     * that need additional checks (e.g., y-parity in [verifySchnorr]).
     *
     * By extracting this into a single method, the JIT compiles one hot path
     * for the expensive mulDoubleG instead of two near-identical method bodies.
     * All copyInto calls use explicit parameters to avoid the Kotlin
     * copyInto$default bridge (bitmask + 3 branches + arraylength per call).
     */
    private fun verifySchnorrCore(
        signature: ByteArray,
        data: ByteArray,
        pub: ByteArray,
        sc: PointScratch,
    ): Boolean {
        if (!liftXCached(sc.entryPx, sc.entryPy, pub)) return false

        val r = sc.entryTmp
        U256.fromBytesInto(r, signature, 0)
        if (U256.cmp(r, FieldP.P) >= 0) return false
        val s = sc.entryTmp2
        U256.fromBytesInto(s, signature, 32)
        if (U256.cmp(s, ScalarN.N) >= 0) return false

        // Build challenge hash input. Reuse scratch byte buffer if message fits,
        // otherwise allocate (rare for Nostr: event IDs are 32 bytes → total 160).
        val hashLen = 64 + 32 + 32 + data.size
        val hashInput = if (hashLen <= sc.hashBuf.size) sc.hashBuf else ByteArray(hashLen)
        CHALLENGE_PREFIX.copyInto(hashInput, 0, 0, 64)
        signature.copyInto(hashInput, 64, 0, 32)
        pub.copyInto(hashInput, 96, 0, 32)
        data.copyInto(hashInput, 128, 0, data.size)
        val eHash = sha256Into(sc.bytesTmp1, hashInput, hashLen)
        // Reuse zInv for e (safe: zInv not used until toAffine, which we skip here)
        val e = sc.zInv
        U256.fromBytesInto(e, eHash, 0)
        if (U256.cmp(e, ScalarN.N) >= 0) U256.subTo(e, e, ScalarN.N) // inline reduce

        // Q = s·G + (-e)·P via Shamir's trick
        ScalarN.negTo(e, e) // negate in-place
        sc.entryPoint.setAffine(sc.entryPx, sc.entryPy) // copies px/py, so entryPx is free
        ECPoint.mulDoubleG(sc.entryResult, s, sc.entryPoint, e, sc)

        if (sc.entryResult.isInfinity()) return false

        // Jacobian x-check: X == r·Z² (2 field ops, no inversion)
        val w = sc.w
        FieldP.sqr(sc.zInv2, sc.entryResult.z, w) // Z²
        FieldP.mul(sc.zInv3, r, sc.zInv2, w) // r·Z²
        // Normalize X before comparison (may be unreduced from lazy fe_add)
        FieldP.reduceSelf(sc.entryResult.x)
        return U256.cmp(sc.entryResult.x, sc.zInv3) == 0
    }

    // ==================== Tweak operations ====================

    /**
     * Add a tweak to a private key: result = (seckey + tweak) mod n. Used by BIP-32.
     *
     * Throws `IllegalArgumentException` for wrong-size inputs and
     * `IllegalStateException` when the result is 0 or >= n (matching the
     * C side which returns 0). The latter is a ~2^-128 cryptographic edge
     * case that indicates an adversarial tweak choice.
     */
    fun privKeyTweakAdd(
        seckey: ByteArray,
        tweak: ByteArray,
    ): ByteArray {
        require(seckey.size == 32 && tweak.size == 32)
        // Use thread-local scratch to avoid 2 intermediate Fe4() allocations.
        // Old path: fromBytes (alloc) + fromBytes (alloc) + add (alloc) + toBytes (alloc) = 4 allocs
        // New path: fromBytesInto (scratch) + fromBytesInto (scratch) + addTo (scratch) + toBytes = 1 alloc
        val sc = ECPoint.getScratch()
        val a = sc.entryTmp
        val b = sc.entryTmp2
        val r = sc.scalarTmp1
        U256.fromBytesInto(a, seckey, 0)
        U256.fromBytesInto(b, tweak, 0)
        // As libsecp256k1's ec_seckey_tweak_add: the key in [1, n), the tweak below n (zero is
        // allowed). Reducing first would accept a tweak of n (≡ 0) or above, which it rejects.
        require(ScalarN.isValid(a)) { "Invalid secret key" }
        require(U256.cmp(b, ScalarN.N) < 0) { "Tweak is not below n" }
        ScalarN.addTo(r, a, b)
        // ScalarN.addTo already reduces mod n, so r < n is guaranteed.
        // The only remaining invalid state is r == 0, which matches the
        // C side's `scalar_is_zero(&r)` failure.
        check(!r.isZero()) { "Tweaked private key is zero — invalid tweak" }
        return U256.toBytes(r)
    }

    /** Multiply a public key by a scalar. Used for ECDH shared secret derivation. */
    fun pubKeyTweakMul(
        pubkey: ByteArray,
        tweak: ByteArray,
    ): ByteArray {
        require(tweak.size == 32)
        val sc = ECPoint.getScratch()
        check(KeyCodec.parsePublicKey(pubkey, sc.entryPx, sc.entryPy))
        val scalar = sc.scalarTmp1
        U256.fromBytesInto(scalar, tweak, 0)
        require(ScalarN.isValid(scalar))

        sc.entryPoint.setAffine(sc.entryPx, sc.entryPy)
        ECPoint.mul(sc.entryResult, sc.entryPoint, scalar, sc)
        check(ECPoint.toAffine(sc.entryResult, sc.entryPx, sc.entryPy, sc))

        return if (pubkey.size == 33) {
            KeyCodec.serializeCompressed(sc.entryPx, sc.entryPy)
        } else {
            KeyCodec.serializeUncompressed(sc.entryPx, sc.entryPy)
        }
    }

    /**
     * ECDH x-only multiplication: computes the x-coordinate of scalar · P.
     *
     * Optimized for the Nostr ECDH use case (NIP-04, NIP-44) where the caller only
     * needs the x-coordinate of the shared secret. This avoids the expensive square
     * root (~267 field ops) needed to decompress the y-coordinate from a compressed
     * public key, because k·(x,y) and k·(x,-y) produce the same x-coordinate
     * (negating a point only flips y: k·(-P) = -(k·P), and negation preserves x).
     *
     * @param xOnlyPub 32-byte x-only public key
     * @param scalar 32-byte scalar (private key)
     * @return 32-byte x-coordinate of the shared point
     */
    fun ecdhXOnly(
        xOnlyPub: ByteArray,
        scalar: ByteArray,
    ): ByteArray {
        require(xOnlyPub.size == 32 && scalar.size == 32)
        val sc = ECPoint.getScratch()
        U256.fromBytesInto(sc.entryTmp, xOnlyPub, 0)
        require(U256.cmp(sc.entryTmp, FieldP.P) < 0)
        val k = sc.scalarTmp1
        U256.fromBytesInto(k, scalar, 0)
        require(ScalarN.isValid(k))

        // Compute y = sqrt(x³ + 7). We need SOME valid y for EC point operations,
        // but the result's x-coordinate is the same regardless of y sign.
        check(KeyCodec.liftX(sc.entryPx, sc.entryPy, sc.entryTmp, sc.entryTmp2)) {
            "Not a valid x-coordinate on secp256k1"
        }

        sc.entryPoint.setAffine(sc.entryPx, sc.entryPy)
        ECPoint.mul(sc.entryResult, sc.entryPoint, k, sc)
        check(ECPoint.toAffineX(sc.entryResult, sc.entryPx, sc))
        return U256.toBytes(sc.entryPx)
    }

    // ==================== Public-key arithmetic (libsecp256k1's ec_pubkey_* family) ====================
    //
    // On public values only (keys, tweaks, points of a protocol such as Cashu's BDHKE). They throw
    // on invalid input; the Schnorr256k1 facade turns that into null.

    /** The 65-byte uncompressed form of a valid 33- or 65-byte public key. */
    fun pubKeyParse(pubkey: ByteArray): ByteArray {
        val x = Fe4()
        val y = Fe4()
        require(KeyCodec.parsePublicKey(pubkey, x, y)) { "Invalid public key" }
        return KeyCodec.serializeUncompressed(x, y)
    }

    /** -P, in the input's format (33 or 65 bytes). */
    fun pubKeyNegate(pubkey: ByteArray): ByteArray {
        val x = Fe4()
        val y = Fe4()
        require(KeyCodec.parsePublicKey(pubkey, x, y)) { "Invalid public key" }
        FieldP.neg(y, y)
        return if (pubkey.size == 33) KeyCodec.serializeCompressed(x, y) else KeyCodec.serializeUncompressed(x, y)
    }

    /** P₁ + … + Pₖ as 65 bytes. Fails on an empty list, an invalid key, or a sum at infinity. */
    fun pubKeyCombine(pubkeys: List<ByteArray>): ByteArray {
        require(pubkeys.isNotEmpty()) { "Nothing to combine" }
        val sc = ECPoint.getScratch()
        val acc = MutablePoint()
        val tmp = MutablePoint()
        val x = Fe4()
        val y = Fe4()
        acc.setInfinity()
        for (p in pubkeys) {
            require(KeyCodec.parsePublicKey(p, x, y)) { "Invalid public key" }
            ECPoint.addMixed(tmp, acc, x, y, sc)
            acc.copyFrom(tmp)
        }
        check(ECPoint.toAffine(acc, x, y, sc)) { "The sum is the point at infinity" }
        return KeyCodec.serializeUncompressed(x, y)
    }

    /**
     * P + tweak·G, in the input's format. The tweak may be zero, as in libsecp256k1; it must be
     * below n. Fails if the result is the point at infinity.
     */
    fun pubKeyTweakAdd(
        pubkey: ByteArray,
        tweak: ByteArray,
    ): ByteArray {
        require(tweak.size == 32)
        val sc = ECPoint.getScratch()
        val x = Fe4()
        val y = Fe4()
        require(KeyCodec.parsePublicKey(pubkey, x, y)) { "Invalid public key" }
        val t = Fe4()
        U256.fromBytesInto(t, tweak, 0)
        require(U256.cmp(t, ScalarN.N) < 0) { "Tweak is not below n" }
        if (!t.isZero()) {
            val tg = MutablePoint()
            ECPoint.mulG(tg, t, sc)
            val sum = MutablePoint()
            ECPoint.addMixed(sum, tg, x, y, sc)
            check(ECPoint.toAffine(sum, x, y, sc)) { "The tweaked key is the point at infinity" }
        }
        return if (pubkey.size == 33) KeyCodec.serializeCompressed(x, y) else KeyCodec.serializeUncompressed(x, y)
    }

    /** n - seckey, for a valid secret key. */
    fun privKeyNegate(seckey: ByteArray): ByteArray {
        require(seckey.size == 32)
        val d = Fe4()
        U256.fromBytesInto(d, seckey, 0)
        require(ScalarN.isValid(d)) { "Invalid secret key" }
        ScalarN.negTo(d, d)
        return U256.toBytes(d)
    }

    /** BIP-340 tagged hash (for tags not cached above). */
    internal fun taggedHash(
        tag: String,
        msg: ByteArray,
    ): ByteArray {
        val tagHash = sha256(tag.encodeToByteArray())
        return sha256(tagHash + tagHash + msg)
    }

    // ==================== Same-Pubkey Batch Verification ====================

    private val BATCH_PREFIX: ByteArray = sha256("BIP0340/batch".encodeToByteArray()).let { it + it }

    /** Signatures per Strauss pass: their wNAF tables share one inversion and 128 doublings. */
    private const val BATCH_CHUNK = 32

    /** Odd multiples R, 3R, …, 15R per point: wNAF window 5. */
    private const val BATCH_TABLE = 8
    private const val BATCH_WINDOW = 5
    private const val BATCH_COEF_BITS = 128

    /** Per-thread buffers for [verifySchnorrBatch], made on a thread's first batch (~80 KB). */
    private class BatchScratch {
        val jac = Array(BATCH_CHUNK * BATCH_TABLE) { MutablePoint() }
        val aff = Array(BATCH_CHUNK * BATCH_TABLE) { AffinePoint() }
        val prods = Array(BATCH_CHUNK * BATCH_TABLE) { Fe4() }
        val wnaf = Array(BATCH_CHUNK) { IntArray(BATCH_COEF_BITS + BATCH_WINDOW + 1) }
        val wnafLen = IntArray(BATCH_CHUNK)
        val wnafTmp = LongArray(4)
        val coef = Fe4()
        val coefBytes = ByteArray(32)
        val coefBlock = ByteArray(32)
        val counter = ByteArray(36)
        val term = Fe4()
        val wide = Wide8()
        val sSum = Fe4()
        val eSum = Fe4()
        val rSum = MutablePoint()
        val two = MutablePoint()
        val accA = MutablePoint()
        val accB = MutablePoint()
        val q = MutablePoint()
        val sum = MutablePoint()
        val negY = Fe4()
        val inv = Fe4()
        val zInv = Fe4()
        val zInv2 = Fe4()
        val zInv3 = Fe4()

        /** The seed hash's input; grows to the largest batch this thread has verified. */
        var seedBuf = ByteArray(0)
    }

    private val batchScratch = ScratchLocal { BatchScratch() }

    /**
     * Batch-verify BIP-340 signatures by the SAME public key. True if and only if every
     * signature is valid, except with probability about 2⁻¹²⁸.
     *
     * BIP-340's batch verification, for one key P:
     *
     *   (Σ aᵢ·sᵢ)·G == Σ aᵢ·Rᵢ + (Σ aᵢ·eᵢ)·P
     *
     * with a₁ = 1 and the other aᵢ 128-bit weights from a CSPRNG (SHA-256 in counter mode)
     * seeded by a tagged hash of every input: the key, each message (with its length) and each
     * signature. Without the weights the check is a plain sum, and errors cancel: (R₁, s₁ + d)
     * and (R₂, s₂ − d) are both invalid but sum to a valid pair. With them, making errors
     * cancel means finding a weight before it is known, which takes about 2¹²⁸ hashes.
     *
     * The left side is one Shamir mulDoubleG. The right side is a Strauss multi-scalar
     * multiplication in chunks of [BATCH_CHUNK]: each Rᵢ gets a wNAF-5 table of odd multiples,
     * made affine with one inversion per chunk, and the chunk's points share ~130 doublings.
     * Per signature: one liftX, one SHA-256 for eᵢ, half of one for aᵢ, ~7 full and ~22 mixed
     * point additions, against ~130 doublings and a table for a single verify.
     *
     * @param pub 32-byte x-only public key (same for all signatures)
     * @param signatures list of 64-byte signatures (R.x || s)
     * @param messages list of messages, same order as signatures
     * @return true if all signatures are valid for this pubkey
     */
    fun verifySchnorrBatch(
        pub: ByteArray,
        signatures: List<ByteArray>,
        messages: List<ByteArray>,
    ): Boolean {
        val n = signatures.size
        require(n == messages.size) { "signatures and messages must have same size" }
        if (n == 0) return true
        if (n == 1) return verifySchnorr(signatures[0], messages[0], pub)
        if (pub.size != 32) return false
        for (sig in signatures) if (sig.size != 64) return false

        val sc = ECPoint.getScratch()
        val b = batchScratch.get()

        val px = sc.entryPx
        val py = sc.entryPy
        if (!liftXCached(px, py, pub)) return false

        // seed = tagged hash of pub || (len(msgᵢ) || msgᵢ)… || sigᵢ…
        var seedLen = 64 + 32
        for (m in messages) seedLen += 4 + m.size
        seedLen += 64 * n
        if (b.seedBuf.size < seedLen) b.seedBuf = ByteArray(seedLen)
        val seedInput = b.seedBuf
        BATCH_PREFIX.copyInto(seedInput, 0)
        pub.copyInto(seedInput, 64)
        var off = 96
        for (m in messages) {
            seedInput[off] = (m.size ushr 24).toByte()
            seedInput[off + 1] = (m.size ushr 16).toByte()
            seedInput[off + 2] = (m.size ushr 8).toByte()
            seedInput[off + 3] = m.size.toByte()
            m.copyInto(seedInput, off + 4)
            off += 4 + m.size
        }
        for (sig in signatures) {
            sig.copyInto(seedInput, off)
            off += 64
        }
        sha256Into(b.counter, seedInput, seedLen) // counter = seed || 4-byte block index

        val r = sc.scalarTmp1
        val s = sc.scalarTmp2
        val e = sc.scalarTmp3
        val rx = sc.entryTmp
        val ry = sc.entryTmp2
        b.sSum.setZero()
        b.eSum.setZero()
        b.rSum.setInfinity()

        var chunkStart = 0
        while (chunkStart < n) {
            val chunkEnd = minOf(chunkStart + BATCH_CHUNK, n)
            var maxLen = 0
            for (i in chunkStart until chunkEnd) {
                val sig = signatures[i]
                val msg = messages[i]
                U256.fromBytesInto(r, sig, 0)
                if (U256.cmp(r, FieldP.P) >= 0) return false
                U256.fromBytesInto(s, sig, 32)
                if (U256.cmp(s, ScalarN.N) >= 0) return false

                // eᵢ = H(rᵢ || pub || msgᵢ)
                val hashLen = 64 + 32 + 32 + msg.size
                val hashInput = if (hashLen <= sc.hashBuf.size) sc.hashBuf else ByteArray(hashLen)
                CHALLENGE_PREFIX.copyInto(hashInput, 0, 0, 64)
                sig.copyInto(hashInput, 64, 0, 32)
                pub.copyInto(hashInput, 96, 0, 32)
                msg.copyInto(hashInput, 128, 0, msg.size)
                sha256Into(sc.bytesTmp1, hashInput, hashLen)
                U256.fromBytesInto(e, sc.bytesTmp1, 0)
                ScalarN.reduceTo(e, e)

                if (!KeyCodec.liftX(rx, ry, r, sc.zInv)) return false

                if (i == 0) {
                    // a₁ = 1
                    ScalarN.addTo(b.sSum, b.sSum, s)
                    ScalarN.addTo(b.eSum, b.eSum, e)
                    b.rSum.setAffine(rx, ry)
                    b.wnafLen[0] = 0
                    continue
                }
                batchWeight(b, i)
                ScalarN.mulTo(b.term, b.coef, s, b.wide)
                ScalarN.addTo(b.sSum, b.sSum, b.term)
                ScalarN.mulTo(b.term, b.coef, e, b.wide)
                ScalarN.addTo(b.eSum, b.eSum, b.term)

                val j = i - chunkStart
                val len = Glv.wnafInto(b.wnaf[j], b.wnafTmp, b.coef, BATCH_WINDOW, BATCH_COEF_BITS)
                b.wnafLen[j] = len
                if (len > maxLen) maxLen = len

                // Odd multiples Rᵢ, 3Rᵢ, …, 15Rᵢ (Jacobian), made affine per chunk below.
                val base = j * BATCH_TABLE
                b.jac[base].setAffine(rx, ry)
                ECPoint.doublePoint(b.two, b.jac[base], sc)
                for (k in 1 until BATCH_TABLE) ECPoint.addPoints(b.jac[base + k], b.jac[base + k - 1], b.two, sc)
            }

            val first = if (chunkStart == 0) 1 else 0 // R₁ went straight into rSum
            val count = chunkEnd - chunkStart
            if (count > first) {
                batchTablesToAffine(b, first * BATCH_TABLE, count * BATCH_TABLE, sc)

                // Strauss: acc = Σ aᵢ·Rᵢ over the chunk, sharing the doublings.
                var cur = b.accA
                var alt = b.accB
                cur.setInfinity()
                for (bit in maxLen - 1 downTo 0) {
                    ECPoint.doublePoint(cur, cur, sc)
                    for (j in first until count) {
                        if (bit >= b.wnafLen[j]) continue
                        val d = b.wnaf[j][bit]
                        if (d == 0) continue
                        val p = b.aff[j * BATCH_TABLE + (if (d > 0) d else -d) / 2]
                        if (d > 0) {
                            ECPoint.addMixed(alt, cur, p.x, p.y, sc)
                        } else {
                            FieldP.neg(b.negY, p.y)
                            ECPoint.addMixed(alt, cur, p.x, b.negY, sc)
                        }
                        val t = cur
                        cur = alt
                        alt = t
                    }
                }
                ECPoint.addPoints(b.sum, b.rSum, cur, sc)
                b.rSum.copyFrom(b.sum)
            }
            chunkStart = chunkEnd
        }

        // Q = (Σaᵢsᵢ)·G − (Σaᵢeᵢ)·P; valid iff Q == Σ aᵢ·Rᵢ.
        ScalarN.negTo(b.eSum, b.eSum)
        sc.entryPoint.setAffine(px, py)
        ECPoint.mulDoubleG(b.q, b.sSum, sc.entryPoint, b.eSum)
        FieldP.neg(b.rSum.y, b.rSum.y)
        ECPoint.addPoints(b.sum, b.q, b.rSum, sc)
        return b.sum.isInfinity()
    }

    /**
     * aᵢ for i ≥ 1: 16 bytes of SHA-256(seed || ⌊i/2⌋), the first half for even i, the second
     * for odd i, as a 128-bit scalar (never 0). Leaves it in [BatchScratch.coef].
     */
    private fun batchWeight(
        b: BatchScratch,
        i: Int,
    ) {
        val block = i ushr 1
        if (i == 1 || (i and 1) == 0) {
            b.counter[32] = (block ushr 24).toByte()
            b.counter[33] = (block ushr 16).toByte()
            b.counter[34] = (block ushr 8).toByte()
            b.counter[35] = block.toByte()
            sha256Into(b.coefBlock, b.counter, 36)
        }
        b.coefBytes.fill(0, 0, 16)
        b.coefBlock.copyInto(b.coefBytes, 16, (i and 1) * 16, (i and 1) * 16 + 16)
        U256.fromBytesInto(b.coef, b.coefBytes, 0)
        if (b.coef.isZero()) b.coef.l0 = 1L
    }

    /** Montgomery's trick over b.jac[from until to] into b.aff: one inversion for the chunk. */
    private fun batchTablesToAffine(
        b: BatchScratch,
        from: Int,
        to: Int,
        sc: PointScratch,
    ) {
        val w = sc.w
        b.prods[from].copyFrom(b.jac[from].z)
        for (k in from + 1 until to) FieldP.mul(b.prods[k], b.prods[k - 1], b.jac[k].z, w)
        FieldP.inv(b.inv, b.prods[to - 1])
        for (k in to - 1 downTo from) {
            if (k > from) {
                FieldP.mul(b.zInv, b.inv, b.prods[k - 1], w)
                FieldP.mul(b.inv, b.inv, b.jac[k].z, w)
            } else {
                b.zInv.copyFrom(b.inv)
            }
            FieldP.sqr(b.zInv2, b.zInv, w)
            FieldP.mul(b.zInv3, b.zInv2, b.zInv, w)
            FieldP.mul(b.aff[k].x, b.jac[k].x, b.zInv2, w)
            FieldP.mul(b.aff[k].y, b.jac[k].y, b.zInv3, w)
        }
    }
}

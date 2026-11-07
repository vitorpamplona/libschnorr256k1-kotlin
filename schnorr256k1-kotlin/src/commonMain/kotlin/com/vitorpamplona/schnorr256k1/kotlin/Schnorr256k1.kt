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
package com.vitorpamplona.schnorr256k1.kotlin

import com.vitorpamplona.crypto.sha2.sha256 as cryptoSha256

/**
 * BIP-340 Schnorr signatures and key operations on secp256k1, in pure Kotlin.
 *
 * The same API as libschnorr256k1-kmp's `com.vitorpamplona.schnorr256k1.Schnorr256k1` (the C
 * library through JNI/cinterop/WASM): same names, argument order and results, so switching
 * between the two is a dependency and import change. Invalid input (wrong length, out-of-range
 * scalar, point not on the curve) returns `null` or `false` instead of throwing, as there.
 *
 * Thread-safe: each thread works in its own scratch buffers.
 *
 * Variable time: running time depends on the secret key and nonce (wNAF scalar multiplication,
 * safegcd inversion). Do not use where timing side channels matter.
 */
public object Schnorr256k1 {
    /** No native library to load; kept for API parity. Touching the object builds the tables. */
    public fun ensureLoaded() {}

    /** 65-byte uncompressed public key (`04 || x || y`) for a 32-byte secret key. */
    public fun pubkeyCreate(seckey: ByteArray): ByteArray? = orNull { Secp256k1.pubkeyCreate(seckey) }

    /** 33-byte compressed public key from a 65-byte (or 33-byte) public key. */
    public fun pubkeyCompress(pubkey: ByteArray): ByteArray? = orNull { Secp256k1.pubKeyCompress(pubkey) }

    /** True if [seckey] is 32 bytes and in [1, n). */
    public fun seckeyVerify(seckey: ByteArray): Boolean = Secp256k1.secKeyVerify(seckey)

    /** BIP-340 signature of [msg] (any length). Derives the public key; see [schnorrSignXOnly]. */
    public fun schnorrSign(
        msg: ByteArray,
        seckey: ByteArray,
        auxrand: ByteArray? = null,
    ): ByteArray? = orNull { Secp256k1.signSchnorr(msg, seckey, auxrand) }

    /**
     * BIP-340 signature with the 32-byte x-only public key already known. No faster than
     * [schnorrSign]: an x-only key does not carry the y parity signing needs. Use
     * [schnorrSignWithPubKey] with the 33-byte compressed key for the fast path. Returns null if
     * [xonlyPub] is not [seckey]'s public key.
     */
    public fun schnorrSignXOnly(
        msg: ByteArray,
        seckey: ByteArray,
        xonlyPub: ByteArray,
        auxrand: ByteArray? = null,
    ): ByteArray? = orNull { Secp256k1.signSchnorrWithXOnlyPubKey(msg, seckey, xonlyPub, auxrand) }

    /**
     * BIP-340 signature with the 33-byte compressed public key (`02`/`03 || x`) already known:
     * skips deriving it, about half the work of [schnorrSign]. Not in libschnorr256k1-kmp's API.
     * The caller must pass [seckey]'s own public key; a wrong one gives an invalid signature.
     */
    public fun schnorrSignWithPubKey(
        msg: ByteArray,
        seckey: ByteArray,
        compressedPub: ByteArray,
        auxrand: ByteArray? = null,
    ): ByteArray? = orNull { Secp256k1.signSchnorrWithPubKey(msg, seckey, compressedPub, auxrand) }

    /** Full BIP-340 verification against a 32-byte x-only public key. */
    public fun schnorrVerify(
        sig: ByteArray,
        msg: ByteArray,
        pub: ByteArray,
    ): Boolean = orFalse { Secp256k1.verifySchnorr(sig, msg, pub) }

    /** Verification without BIP-340's y-parity check of R (see Secp256k1.verifySchnorrFast). */
    public fun schnorrVerifyFast(
        sig: ByteArray,
        msg: ByteArray,
        pub: ByteArray,
    ): Boolean = orFalse { Secp256k1.verifySchnorrFast(sig, msg, pub) }

    /** True if every signature in [sigs] is valid for the matching message under [pub]. */
    public fun schnorrVerifyBatch(
        pub: ByteArray,
        sigs: List<ByteArray>,
        msgs: List<ByteArray>,
    ): Boolean = sigs.size == msgs.size && orFalse { Secp256k1.verifySchnorrBatch(pub, sigs, msgs) }

    /** `(seckey + tweak) mod n`, or null if the result is zero or an input is invalid. */
    public fun privkeyTweakAdd(
        seckey: ByteArray,
        tweak: ByteArray,
    ): ByteArray? = orNull { Secp256k1.privKeyTweakAdd(seckey, tweak) }

    /** `pubkey * tweak`, in the input's format (33 or 65 bytes). */
    public fun pubkeyTweakMul(
        pubkey: ByteArray,
        tweak: ByteArray,
    ): ByteArray? = orNull { Secp256k1.pubKeyTweakMul(pubkey, tweak) }

    /** 32-byte x coordinate of `scalar * P`, P lifted from the x-only [xonlyPub] (NIP-04/NIP-44). */
    public fun ecdhXOnly(
        xonlyPub: ByteArray,
        scalar: ByteArray,
    ): ByteArray? = orNull { Secp256k1.ecdhXOnly(xonlyPub, scalar) }

    public fun sha256(data: ByteArray): ByteArray? = cryptoSha256(data)

    /** BIP-340 tagged hash: `sha256(sha256(tag) || sha256(tag) || msg)`. */
    public fun taggedHash(
        tag: String,
        msg: ByteArray,
    ): ByteArray? = Secp256k1.taggedHash(tag, msg)

    private inline fun orNull(block: () -> ByteArray): ByteArray? =
        try {
            block()
        } catch (_: IllegalArgumentException) {
            null
        } catch (_: IllegalStateException) {
            null
        }

    private inline fun orFalse(block: () -> Boolean): Boolean =
        try {
            block()
        } catch (_: IllegalArgumentException) {
            false
        } catch (_: IllegalStateException) {
            false
        }
}

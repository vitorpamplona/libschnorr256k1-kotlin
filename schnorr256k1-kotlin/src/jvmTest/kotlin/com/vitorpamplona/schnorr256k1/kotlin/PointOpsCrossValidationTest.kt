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

import java.util.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import fr.acinq.secp256k1.Secp256k1 as Acinq

/**
 * pubkeyParse, pubkeyNegate, pubkeyCombine, pubkeyTweakAdd and privkeyNegate against libsecp256k1
 * (ACINQ's secp256k1-kmp): the same results on valid input, and a rejection wherever
 * libsecp256k1 rejects. ACINQ returns 65-byte keys; ours keep the input's format, so results are
 * compared after parsing.
 */
class PointOpsCrossValidationTest {
    private val acinq = Acinq.get()
    private val rng = Random(0x5EC9256B1L)
    private val p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f".hexToByteArray()
    private val n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".hexToByteArray()

    private fun bytes(k: Int) = ByteArray(k).also { rng.nextBytes(it) }

    private fun seckey(): ByteArray {
        while (true) {
            val k = bytes(32)
            if (acinq.secKeyVerify(k)) return k
        }
    }

    private fun pub65() = acinq.pubkeyCreate(seckey())

    private fun pub33() = acinq.pubKeyCompress(pub65())

    /** ACINQ's result, or null where it throws. */
    private fun ref(f: () -> ByteArray): ByteArray? =
        try {
            f()
        } catch (_: Exception) {
            null
        }

    private fun same(
        expected: ByteArray?,
        actual: ByteArray?,
        what: String,
    ) {
        if (expected == null) {
            assertNull(actual, "$what: libsecp256k1 rejects, we returned ${actual?.toHexKey()}")
        } else {
            assertContentEquals(expected, actual?.let { Schnorr256k1.pubkeyParse(it) ?: it }, what)
        }
    }

    @Test
    fun parseMatchesLibsecp256k1() {
        repeat(300) {
            val k65 = pub65()
            val k33 = acinq.pubKeyCompress(k65)
            assertContentEquals(acinq.pubkeyParse(k65), Schnorr256k1.pubkeyParse(k65))
            assertContentEquals(acinq.pubkeyParse(k33), Schnorr256k1.pubkeyParse(k33))
            // random x: on the curve about half the time
            val x = byteArrayOf(if (it % 2 == 0) 2 else 3) + bytes(32)
            same(ref { acinq.pubkeyParse(x) }, Schnorr256k1.pubkeyParse(x), "parse ${x.toHexKey()}")
            // a valid x with the wrong y
            val bad = k65.copyOf().also { b -> b[64] = (b[64] + 1).toByte() }
            same(ref { acinq.pubkeyParse(bad) }, Schnorr256k1.pubkeyParse(bad), "parse off-curve 65")
        }
        val xp = byteArrayOf(2) + p
        same(ref { acinq.pubkeyParse(xp) }, Schnorr256k1.pubkeyParse(xp), "x = p")
        // A non-canonical 65-byte key: x + p fits in 256 bits only for a tiny x, so find a point
        // with one; its encoding with x + p is the same point modulo p, which libsecp256k1 rejects.
        val small = (1..100).map { i -> ByteArray(32).also { it[31] = i.toByte() } }.first { x -> Schnorr256k1.pubkeyParse(byteArrayOf(2) + x) != null }
        val point = Schnorr256k1.pubkeyParse(byteArrayOf(2) + small)!!
        val xPlusP = Fe4()
        U256.addTo(xPlusP, U256.fromBytes(small), U256.fromBytes(p))
        val nonCanonical = byteArrayOf(4) + U256.toBytes(xPlusP) + point.copyOfRange(33, 65)
        same(ref { acinq.pubkeyParse(nonCanonical) }, Schnorr256k1.pubkeyParse(nonCanonical), "x + p")
        assertNull(Schnorr256k1.pubkeyParse(nonCanonical), "x + p accepted")
        for (len in listOf(0, 32, 34, 64, 66)) assertNull(Schnorr256k1.pubkeyParse(ByteArray(len) { 2 }))
    }

    /** Hybrid keys (06/07 || x || y): libsecp256k1 accepts them when the prefix matches y's parity. */
    @Test
    fun hybridKeysMatchLibsecp256k1() {
        repeat(50) {
            val k = pub65()
            val even = k[64].toInt() and 1 == 0
            val good = k.copyOf().also { h -> h[0] = if (even) 6 else 7 }
            val wrongParity = k.copyOf().also { h -> h[0] = if (even) 7 else 6 }
            same(ref { acinq.pubkeyParse(good) }, Schnorr256k1.pubkeyParse(good), "hybrid")
            same(ref { acinq.pubkeyParse(wrongParity) }, Schnorr256k1.pubkeyParse(wrongParity), "hybrid, wrong parity")
        }
    }

    @Test
    fun negateMatchesLibsecp256k1() {
        repeat(300) {
            val k = if (it % 2 == 0) pub65() else pub33()
            val ours = Schnorr256k1.pubkeyNegate(k)
            assertEquals(k.size, ours?.size, "negate keeps the input's format")
            same(acinq.pubKeyNegate(k), ours, "negate")
        }
    }

    @Test
    fun combineMatchesLibsecp256k1() {
        repeat(200) {
            val keys = List(1 + rng.nextInt(6)) { j -> if ((it + j) % 2 == 0) pub65() else pub33() }
            assertContentEquals(acinq.pubKeyCombine(keys.toTypedArray()), Schnorr256k1.pubkeyCombine(keys))
        }
        val k = pub33()
        val doubled = Schnorr256k1.pubkeyCombine(listOf(k, k))
        assertContentEquals(acinq.pubKeyCombine(arrayOf(k, k)), doubled, "P + P")
        val sum = Schnorr256k1.pubkeyCombine(listOf(k, Schnorr256k1.pubkeyNegate(k)!!))
        same(ref { acinq.pubKeyCombine(arrayOf(k, acinq.pubKeyNegate(k))) }, sum, "P + (-P)")
        assertNull(Schnorr256k1.pubkeyCombine(emptyList()))
        assertNull(Schnorr256k1.pubkeyCombine(listOf(k, byteArrayOf(2) + p)))
    }

    @Test
    fun tweakAddMatchesLibsecp256k1() {
        repeat(300) {
            val k = if (it % 2 == 0) pub65() else pub33()
            val t = if (it % 3 == 0) seckey() else bytes(32)
            val ours = Schnorr256k1.pubkeyTweakAdd(k, t)
            same(ref { acinq.pubKeyTweakAdd(k, t) }, ours, "tweakAdd ${t.toHexKey()}")
            if (ours != null) assertEquals(k.size, ours.size, "tweakAdd keeps the input's format")
        }
        val k = pub33()
        same(ref { acinq.pubKeyTweakAdd(k, ByteArray(32)) }, Schnorr256k1.pubkeyTweakAdd(k, ByteArray(32)), "zero tweak")
        same(ref { acinq.pubKeyTweakAdd(k, n) }, Schnorr256k1.pubkeyTweakAdd(k, n), "tweak = n")
        // P = d·G with tweak n - d: the result is the point at infinity
        val d = seckey()
        val pd = acinq.pubKeyCompress(acinq.pubkeyCreate(d))
        val negD = acinq.privKeyNegate(d)
        same(ref { acinq.pubKeyTweakAdd(pd, negD) }, Schnorr256k1.pubkeyTweakAdd(pd, negD), "to infinity")
    }

    @Test
    fun privkeyNegateMatchesLibsecp256k1() {
        repeat(300) {
            val k = if (it % 4 == 0) bytes(32) else seckey()
            assertEquals(
                ref { acinq.privKeyNegate(k) }?.toHexKey(),
                Schnorr256k1.privkeyNegate(k)?.toHexKey(),
                "privkeyNegate ${k.toHexKey()}",
            )
        }
        assertNull(Schnorr256k1.privkeyNegate(ByteArray(32)))
        assertNull(Schnorr256k1.privkeyNegate(n))
    }
}

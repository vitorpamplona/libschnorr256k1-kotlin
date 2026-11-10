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

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * ecdhXOnly runs on an isomorphic curve and never lifts x (Secp256k1.ecdhXOnly): its result must be
 * x(k·P) for either lift of x, which tweak-mul of 02 || x computes the usual way, and it must reject
 * an x with no point.
 */
class EcdhXOnlyTest {
    private fun bytes(
        tag: Int,
        i: Int,
    ) = Schnorr256k1.sha256(byteArrayOf(tag.toByte(), (i shr 8).toByte(), i.toByte()))!!

    @Test
    fun matchesTweakMulOfTheLift() {
        var odd = 0
        for (i in 0 until 200) {
            val pub33 = Schnorr256k1.pubkeyCompress(Schnorr256k1.pubkeyCreate(bytes(1, i))!!)!!
            if (pub33[0] == 0x03.toByte()) odd++
            val x = pub33.copyOfRange(1, 33)
            val k = bytes(2, i)
            val even = byteArrayOf(0x02) + x
            val want = Schnorr256k1.pubkeyTweakMul(even, k)!!.copyOfRange(1, 33)
            assertContentEquals(want, Schnorr256k1.ecdhXOnly(x, k), "key $i")
        }
        assertTrue(odd in 70..130, "keys of both parities: $odd odd")
    }

    @Test
    fun rejectsAnXWithNoPoint() {
        var rejected = 0
        for (i in 0 until 200) {
            val x = bytes(3, i)
            val k = bytes(4, i)
            val lifted = Schnorr256k1.pubkeyTweakMul(byteArrayOf(0x02) + x, k)
            if (lifted == null) {
                rejected++
                assertNull(Schnorr256k1.ecdhXOnly(x, k), "x $i has no point")
            } else {
                assertContentEquals(lifted.copyOfRange(1, 33), Schnorr256k1.ecdhXOnly(x, k), "x $i")
            }
        }
        assertTrue(rejected in 70..130, "about half of random x have no point: $rejected")
        // BIP-340 vector 5's key, and p itself
        assertNull(Schnorr256k1.ecdhXOnly("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34".hexToByteArray(), bytes(4, 0)))
        assertNull(Schnorr256k1.ecdhXOnly("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F".hexToByteArray(), bytes(4, 0)))
    }
}

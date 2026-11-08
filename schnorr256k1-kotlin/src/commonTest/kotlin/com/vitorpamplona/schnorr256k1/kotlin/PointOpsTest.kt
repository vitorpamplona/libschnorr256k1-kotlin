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

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The point operations' algebra, on every platform (PointOpsCrossValidationTest checks them
 * against libsecp256k1 on the JVM): negation, addition and tweaks agree with key derivation.
 */
class PointOpsTest {
    private val rnd = Random(256)

    private fun seckey(): ByteArray {
        while (true) {
            val k = rnd.nextBytes(32)
            if (Schnorr256k1.seckeyVerify(k)) return k
        }
    }

    private fun pub(d: ByteArray) = Schnorr256k1.pubkeyCreate(d)!!

    @Test
    fun negatingTheKeyNegatesThePoint() {
        repeat(50) {
            val d = seckey()
            val negD = Schnorr256k1.privkeyNegate(d)!!
            assertContentEquals(Schnorr256k1.pubkeyNegate(pub(d)), pub(negD))
            assertContentEquals(d, Schnorr256k1.privkeyNegate(negD))
        }
    }

    @Test
    fun combineIsAddition() {
        repeat(50) {
            val a = seckey()
            val b = seckey()
            val sum = Schnorr256k1.privkeyTweakAdd(a, b) ?: return@repeat
            assertContentEquals(pub(sum), Schnorr256k1.pubkeyCombine(listOf(pub(a), pub(b))))
            assertContentEquals(pub(sum), Schnorr256k1.pubkeyTweakAdd(pub(a), b))
            assertContentEquals(
                Schnorr256k1.pubkeyCompress(pub(sum)),
                Schnorr256k1.pubkeyTweakAdd(Schnorr256k1.pubkeyCompress(pub(a))!!, b),
            )
        }
    }

    @Test
    fun aPointPlusItsNegationIsRejected() {
        val p = pub(seckey())
        assertNull(Schnorr256k1.pubkeyCombine(listOf(p, Schnorr256k1.pubkeyNegate(p)!!)))
        val d = seckey()
        assertNull(Schnorr256k1.pubkeyTweakAdd(pub(d), Schnorr256k1.privkeyNegate(d)!!))
    }

    @Test
    fun parseDecompressesAndValidates() {
        repeat(50) {
            val p65 = pub(seckey())
            assertContentEquals(p65, Schnorr256k1.pubkeyParse(Schnorr256k1.pubkeyCompress(p65)!!))
        }
        assertNotNull(Schnorr256k1.pubkeyParse(Schnorr256k1.pubkeyCompress(pub(seckey()))!!))
        val offCurve = pub(seckey()).copyOf().also { it[64] = (it[64] + 1).toByte() }
        assertNull(Schnorr256k1.pubkeyParse(offCurve))
    }
}

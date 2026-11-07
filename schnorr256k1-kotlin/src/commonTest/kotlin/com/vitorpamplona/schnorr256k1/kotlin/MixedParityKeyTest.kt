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
import kotlin.test.assertTrue

/**
 * P and -P share an x coordinate. Verify works on the even-y point lifted from an x-only key, while
 * tweak-mul works on whatever point it is given: any per-x cache shared by the two would hand one
 * of them the other's tables (libschnorr256k1 has this bug). Interleave them on odd-y keys.
 */
class MixedParityKeyTest {
    @Test
    fun verifyAndTweakMulOnBothPointsOfOneX() {
        val r = Random(0x0DD)
        var n = 0
        while (n < 50) {
            val sk = r.nextBytes(32)
            if (!Schnorr256k1.seckeyVerify(sk)) continue
            val pub = Schnorr256k1.pubkeyCreate(sk)!!
            if ((pub[64].toInt() and 1) == 0) continue // odd-y keys: -P is the even-y lift of x
            val tweak = r.nextBytes(32)
            if (!Schnorr256k1.seckeyVerify(tweak)) continue
            n++
            val compressed = Schnorr256k1.pubkeyCompress(pub)!!
            val xOnly = compressed.copyOfRange(1, 33)
            val msg = r.nextBytes(32)
            val sig = Schnorr256k1.schnorrSign(msg, sk)!!

            val tweaked = Schnorr256k1.pubkeyTweakMul(pub, tweak)!!
            assertTrue(Schnorr256k1.schnorrVerify(sig, msg, xOnly), "verify after tweak-mul of the odd-y key")
            assertContentEquals(tweaked, Schnorr256k1.pubkeyTweakMul(pub, tweak), "tweak-mul after verify")
            // tweak*P must be the point of (sk*tweak mod n)*G
            val product = Secp256k1.pubkeyCreate(ScalarN.mul(U256.fromBytes(sk), U256.fromBytes(tweak)).let { U256.toBytes(it) })
            assertContentEquals(product, tweaked, "tweak*P == (sk*tweak)*G")
        }
    }
}

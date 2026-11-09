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

import java.math.BigInteger
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * FieldP against BigInteger on inputs that reach the rare carry paths: limbs drawn from 0, 1, -1,
 * P0 and their neighbours as well as at random, so values in [p, 2^256) (unreduced, as lazy add and
 * mul leave them), sums that carry out of 2^256 twice, differences that wrap twice and products
 * whose reduction carries out of 2^256 all come up. Outputs may be unreduced; they are compared
 * mod p, and must stay below 2^256.
 */
class FieldPReferenceTest {
    private val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    private val two256 = BigInteger.ONE.shiftLeft(256)
    private val r = Random(0x5EC9)
    private val special = longArrayOf(0L, 1L, 2L, -1L, -2L, -4294968273L, -4294968272L, -4294968274L, 4294968273L, 4294968272L, Long.MIN_VALUE, Long.MAX_VALUE)

    private fun limb() = if (r.nextInt(3) == 0) r.nextLong() else special[r.nextInt(special.size)]

    private fun fe() = Fe4(limb(), limb(), limb(), limb())

    private fun big(a: Fe4): BigInteger {
        var v = BigInteger.ZERO
        for (l in longArrayOf(a.l3, a.l2, a.l1, a.l0)) v = v.shiftLeft(64).or(BigInteger(java.lang.Long.toUnsignedString(l)))
        return v
    }

    private fun check(
        what: String,
        a: Fe4,
        b: Fe4?,
        out: Fe4,
        expected: BigInteger,
    ) {
        val got = big(out)
        assertEquals(true, got < two256, "$what out of range")
        assertEquals(expected.mod(p), got.mod(p), "$what a=${big(a).toString(16)} b=${b?.let { big(it).toString(16) }}")
    }

    /** A value within [k] below 2^256: in [2^256 - k, 2^256). */
    private fun nearTop(k: Long) = Fe4(-1L - r.nextLong(k), -1L, -1L, -1L)

    @Test
    fun addThatCarriesOutOfTwoToThe256Twice() {
        // a + b >= 2^257 - C: both within C of 2^256, so the first fold carries out again.
        val out = Fe4()
        repeat(100_000) {
            val a = nearTop(4294968273L)
            val b = nearTop(4294968273L)
            FieldP.add(out, a, b)
            check("add near 2^256", a, b, out, big(a) + big(b))
        }
    }

    @Test
    fun subThatWrapsTwice() {
        // b >= a + p + 1 with a below C: the first subtraction of C wraps, and it takes 2p.
        val out = Fe4()
        repeat(100_000) {
            val a = Fe4(r.nextLong(4294968273L), 0L, 0L, 0L)
            val b = nearTop(4294968273L - a.l0) // b in [2^256 - (C - a), 2^256) = [a + p, 2^256)
            FieldP.sub(out, a, b)
            check("sub wrapping twice", a, b, out, big(a) - big(b))
        }
    }

    @Test
    fun addSubMulSqrNegHalfMatchBigInteger() {
        val out = Fe4()
        val w = Wide8()
        repeat(400_000) {
            val a = fe()
            val b = fe()
            val ba = big(a)
            val bb = big(b)
            FieldP.add(out, a, b)
            check("add", a, b, out, ba + bb)
            FieldP.sub(out, a, b)
            check("sub", a, b, out, ba - bb)
            FieldP.mul(out, a, b, w)
            check("mul", a, b, out, ba * bb)
            FieldP.sqr(out, a, w)
            check("sqr", a, null, out, ba * ba)
            FieldP.neg(out, a)
            check("neg", a, null, out, ba.negate())
            FieldP.half(out, a)
            check("half", a, null, out, ba * BigInteger.TWO.modInverse(p))
        }
    }
}

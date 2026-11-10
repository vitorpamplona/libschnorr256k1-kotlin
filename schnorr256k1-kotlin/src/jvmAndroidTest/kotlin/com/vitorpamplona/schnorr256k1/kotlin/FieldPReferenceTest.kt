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
 * mod p, and must stay below 2^256. In jvmAndroidTest, so it also runs on the Android host and on
 * devices, which take the fused reduction (reduceWideInline) and their own multiply-high.
 */
class FieldPReferenceTest {
    private val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    private val two256 = BigInteger.ONE.shiftLeft(256)
    private val r = Random(0x5EC9)
    private val special = longArrayOf(0L, 1L, 2L, -1L, -2L, -4294968273L, -4294968272L, -4294968274L, 4294968273L, 4294968272L, Long.MIN_VALUE, Long.MAX_VALUE)

    // BigInteger is much slower on ART (an emulator in CI): fewer random cases there.
    private val onAndroid = System.getProperty("java.vm.name") == "Dalvik"
    private val randomCases = if (onAndroid) 20_000 else 100_000
    private val targetedCases = if (onAndroid) 20_000 else 100_000

    // 1/2 mod p. Not BigInteger.TWO: Android has it from API 33 only, and minSdk is 26.
    private val half = BigInteger.valueOf(2).modInverse(p)

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
        repeat(targetedCases) {
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
        repeat(targetedCases) {
            val a = Fe4(r.nextLong(4294968273L), 0L, 0L, 0L)
            val b = nearTop(4294968273L - a.l0) // b in [2^256 - (C - a), 2^256) = [a + p, 2^256)
            FieldP.sub(out, a, b)
            check("sub wrapping twice", a, b, out, big(a) - big(b))
        }
    }

    @Test
    fun reductionThatCarriesOutOfTwoToThe256() {
        // A 512-bit lo + hi·2^256 whose first fold, lo + hi·C, leaves limbs 1-3 all ones: the carry
        // fold then carries into limb 2 and out of 2^256 (the rare path), for FieldP.reduceWide (JVM,
        // native) and reduceWideInline (Android's fused multiply).
        val mask = two256 - BigInteger.ONE
        val c = BigInteger.valueOf(4294968273L)
        val w = Wide8()
        val out = Fe4()
        val out2 = Fe4()
        repeat(targetedCases / 2) {
            val hi = big(fe())
            val x = BigInteger(java.lang.Long.toUnsignedString(limb()))
            val fold1 = two256 - BigInteger.ONE.shiftLeft(64) + x // limbs 1-3 all ones, limb 0 = x
            val lo = (fold1 - hi * c).and(mask)
            val l = lo.toByteArray().let { b -> ByteArray(32).also { o -> b.copyInto(o, 32 - minOf(32, b.size), maxOf(0, b.size - 32)) } }
            val h = hi.toByteArray().let { b -> ByteArray(32).also { o -> b.copyInto(o, 32 - minOf(32, b.size), maxOf(0, b.size - 32)) } }
            val lf = U256.fromBytes(l)
            val hf = U256.fromBytes(h)
            w.l0 = lf.l0
            w.l1 = lf.l1
            w.l2 = lf.l2
            w.l3 = lf.l3
            w.l4 = hf.l0
            w.l5 = hf.l1
            w.l6 = hf.l2
            w.l7 = hf.l3
            val expected = lo + hi.shiftLeft(256)
            FieldP.reduceWide(out, w)
            check("reduceWide", lf, hf, out, expected)
            reduceWideInline(out2, w) { a, b -> unsignedMultiplyHigh(a, b) }
            check("reduceWideInline", lf, hf, out2, expected)
        }
    }

    @Test
    fun addSubMulSqrNegHalfMatchBigInteger() {
        val out = Fe4()
        val w = Wide8()
        repeat(randomCases) {
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
            check("half", a, null, out, ba * half)
        }
    }
}

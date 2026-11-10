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
import kotlin.test.assertEquals

/** safegcd inversion against Fermat's a^(m-2), on edge values and random inputs. */
class SafeGcdTest {
    private fun same(
        a: Fe4,
        b: Fe4,
    ) = a.l0 == b.l0 && a.l1 == b.l1 && a.l2 == b.l2 && a.l3 == b.l3

    private fun str(a: Fe4) = "[${a.l3.toULong().toString(16)}, ${a.l2.toULong().toString(16)}, ${a.l1.toULong().toString(16)}, ${a.l0.toULong().toString(16)}]"

    private fun edges(m: Fe4): List<Fe4> {
        val out = mutableListOf<Fe4>()
        for (k in 1L..5L) out += Fe4(k, 0, 0, 0)
        for (k in 1L..5L) out += Fe4(m.l0 - k, m.l1, m.l2, m.l3) // m - k
        for (b in listOf(1, 61, 62, 63, 64, 124, 186, 248, 255)) {
            val f = Fe4()
            when (b / 64) {
                0 -> f.l0 = 1L shl b
                1 -> f.l1 = 1L shl (b - 64)
                2 -> f.l2 = 1L shl (b - 128)
                else -> f.l3 = 1L shl (b - 192)
            }
            out += f
        }
        out += Fe4(-1L, -1L, -1L, 0x7FFFFFFFFFFFFFFFL)
        out += Fe4(0x3FFFFFFFFFFFFFFFL, 0, 0, 0)
        out += Fe4(-1L, 0, 0, 0)
        return out
    }

    @Test
    fun jacobiMatchesTheSquareRoot() {
        val r = Random(0x7AC0B1)
        val values =
            edges(FieldP.P) + List(20_000) { Fe4(r.nextLong(), r.nextLong(), r.nextLong(), r.nextLong()) } +
                List(5) { Fe4(FieldP.P.l0 + 1 + it, -1L, -1L, -1L) } + listOf(Fe4(0, 0, 0, 0), FieldP.P)
        val root = Fe4()
        val t = Fe4()
        var squares = 0
        for (x in values) {
            val want = FieldP.sqrt(root, x)
            if (want) squares++
            assertEquals(want, FieldP.isSquare(x), "isSquare(${str(x)})")
            t.copyFrom(x)
            FieldP.reduceSelf(t)
            if (t.isZero()) continue
            // 25 rounds settle every one of these: the fallback to sqrt is not what passed them
            assertEquals(if (want) 1 else -1, SafeGcd.jacobiMaybe(t, SafeGcd.P), "jacobi(${str(x)})")
        }
        assertEquals(true, squares in 9_000..11_000, "about half are squares: $squares")
    }

    @Test
    fun fieldMatchesFermat() {
        val r = Random(0x5AFE)
        val values =
            edges(FieldP.P) + List(20_000) { Fe4(r.nextLong(), r.nextLong(), r.nextLong(), r.nextLong()) } +
                // unreduced inputs in [p, 2^256), which the lazy field arithmetic produces
                List(5) { Fe4(FieldP.P.l0 + 1 + it, -1L, -1L, -1L) } + listOf(Fe4(-1L, -1L, -1L, -1L)) // p + k, k >= 1 (p itself is 0)
        val a = Fe4()
        val b = Fe4()
        val one = Fe4()
        for (x in values) {
            if (x.isZero()) continue
            FieldP.inv(a, x)
            FieldP.invFermat(b, x)
            FieldP.reduceSelf(b)
            assertEquals(true, same(a, b), "inv(${str(x)}): safegcd ${str(a)} vs Fermat ${str(b)}")
            FieldP.mul(one, a, x)
            FieldP.reduceSelf(one)
            assertEquals(true, same(one, Fe4(1, 0, 0, 0)), "x * inv(x) != 1 for ${str(x)}")
        }
        // in place
        val x = Fe4(123456789L, 0, 0, 1L)
        val expect = Fe4()
        FieldP.inv(expect, x)
        FieldP.inv(x, x)
        assertEquals(true, same(x, expect))
    }

    @Test
    fun scalarMatchesFermat() {
        val r = Random(0x5CA1)
        val values = edges(ScalarN.N) + List(3_000) { ScalarN.reduce(Fe4(r.nextLong(), r.nextLong(), r.nextLong(), r.nextLong())) }
        for (x in values) {
            if (x.isZero()) continue
            val a = ScalarN.inv(x)
            val b = ScalarN.invFermat(x)
            assertEquals(true, same(a, b), "scalar inv(${str(x)}): safegcd ${str(a)} vs Fermat ${str(b)}")
            assertEquals(true, same(ScalarN.mul(a, x), Fe4(1, 0, 0, 0)), "x * inv(x) != 1 mod n for ${str(x)}")
        }
    }
}

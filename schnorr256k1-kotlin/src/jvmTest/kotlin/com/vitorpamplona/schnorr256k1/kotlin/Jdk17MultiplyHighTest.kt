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
 * The Java 17 path of unsignedMultiplyHigh (Math.unsignedMultiplyHigh is Java 18+), checked
 * against Math.unsignedMultiplyHigh and against BigInteger, so it is tested on the JDK the build
 * runs on.
 */
class Jdk17MultiplyHighTest {
    private fun exact(
        a: Long,
        b: Long,
    ): Long {
        val u = BigInteger.ONE.shiftLeft(64)

        fun unsigned(x: Long) = BigInteger.valueOf(x).let { if (x < 0) it.add(u) else it }
        return unsigned(a).multiply(unsigned(b)).shiftRight(64).toLong()
    }

    @Test
    fun matchesTheJava18IntrinsicAndBigInteger() {
        val edges = listOf(0L, 1L, -1L, Long.MAX_VALUE, Long.MIN_VALUE, 0xFFFFFFFFL, -0x100000000L, 0x1000003D1L)
        val r = Random(17)
        val values = edges + List(2000) { r.nextLong() }
        for (a in values) {
            for (b in if (a in edges) values else edges + r.nextLong()) {
                val v = unsignedMultiplyHighFromSigned(a, b)
                assertEquals(Math.unsignedMultiplyHigh(a, b), v, "a=$a b=$b")
                assertEquals(exact(a, b), v, "a=$a b=$b")
            }
        }
    }
}

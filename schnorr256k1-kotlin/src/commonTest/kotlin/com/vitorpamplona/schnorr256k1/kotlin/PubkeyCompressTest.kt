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
import kotlin.test.assertNotSame
import kotlin.test.assertNull

/**
 * [Schnorr256k1.pubkeyCompress] on every input form libsecp256k1's parser takes or refuses: the
 * result is copied from the input bytes, so each form's validation is what decides it.
 */
class PubkeyCompressTest {
    private val gx = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    private val gy = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8" // even
    private val negGy = "B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777" // p - gy, odd
    private val p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"

    private fun compress(hex: String) = Schnorr256k1.pubkeyCompress(hex.hexToByteArray())

    @Test
    fun uncompressedEvenAndOddY() {
        assertContentEquals("02$gx".hexToByteArray(), compress("04$gx$gy"))
        assertContentEquals("03$gx".hexToByteArray(), compress("04$gx$negGy"))
    }

    @Test
    fun hybridKeysNeedTheirPrefixToMatchY() {
        assertContentEquals("02$gx".hexToByteArray(), compress("06$gx$gy"))
        assertContentEquals("03$gx".hexToByteArray(), compress("07$gx$negGy"))
        assertNull(compress("07$gx$gy"))
        assertNull(compress("06$gx$negGy"))
    }

    @Test
    fun compressedKeysComeBackAsACopy() {
        val even = "02$gx".hexToByteArray()
        val odd = "03$gx".hexToByteArray()
        val c = Schnorr256k1.pubkeyCompress(even)
        assertContentEquals(even, c)
        assertNotSame(even, c)
        assertContentEquals(odd, Schnorr256k1.pubkeyCompress(odd))
    }

    @Test
    fun pointsOffTheCurveFail() {
        // gy + 1 is not G's y; BIP-340 vector 5's key has no point at all.
        assertNull(compress("04$gx" + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B9"))
        assertNull(compress("02EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"))
    }

    @Test
    fun coordinatesNotBelowPFail() {
        assertNull(compress("02$p"))
        assertNull(compress("04$p$gy"))
        assertNull(compress("04$gx$p"))
    }

    @Test
    fun otherSizesAndPrefixesFail() {
        assertNull(compress("05$gx$gy"))
        assertNull(compress("04$gx"))
        assertNull(compress("01$gx"))
        assertNull(Schnorr256k1.pubkeyCompress(ByteArray(0)))
    }
}

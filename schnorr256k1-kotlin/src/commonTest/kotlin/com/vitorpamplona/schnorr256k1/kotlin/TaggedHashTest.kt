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

import com.vitorpamplona.crypto.sha2.sha256
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals

class TaggedHashTest {
    @Test
    fun matchesSha256OfTheWholeBufferAtEveryLength() {
        val r = Random(0x7A6)
        for (tag in listOf("BIP0340/challenge", "BIP0340/aux", "BIP0340/nonce", "BIP0340/batch")) {
            val prefix = sha256(tag.encodeToByteArray()).let { it + it }
            val hash = TaggedHash(prefix)
            // 64 (prefix only) to 330: tails that pad within one block, need a second (55, 56 and
            // up), and fill whole blocks.
            for (len in 64..330) {
                val buf = prefix + r.nextBytes(len - 64) + r.nextBytes(7) // bytes past len are ignored
                val expected = sha256(buf.copyOf(len))
                assertContentEquals(expected, hash.hashInto(ByteArray(32), buf, len), "$tag, length $len")
            }
        }
    }
}

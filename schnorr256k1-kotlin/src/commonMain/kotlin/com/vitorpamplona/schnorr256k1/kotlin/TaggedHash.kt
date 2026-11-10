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

/**
 * A BIP-340 tagged hash, SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ data), for one tag. Callers keep
 * the 64-byte prefix in buf[0, 64) and the data after it, and [hashInto] hashes buf[0, len).
 *
 * Where SHA-256 is fast (the JVM's and Android's, hardware-accelerated) it hashes the buffer as
 * it is. Kotlin/Native's SHA-256 is pure Kotlin, so there it starts from the state after the
 * prefix (one 64-byte block, compressed once per tag) and skips that block on every call.
 */
internal expect class TaggedHash(
    prefix: ByteArray,
) {
    /** SHA-256 of buf[0, len) into [out], where buf[0, 64) is this tag's prefix. */
    fun hashInto(
        out: ByteArray,
        buf: ByteArray,
        len: Int,
    ): ByteArray
}

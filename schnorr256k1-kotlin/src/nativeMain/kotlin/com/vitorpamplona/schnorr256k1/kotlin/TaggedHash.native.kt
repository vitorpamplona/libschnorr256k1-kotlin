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
 * Starts from the state after the tag prefix, so each call compresses one 64-byte block fewer. The
 * compression is FIPS 180-4's own (crypto-kmp keeps its compression function internal); TaggedHashTest
 * checks the result against crypto-kmp's sha256 at every length from 64 to 330 bytes.
 */
internal actual class TaggedHash actual constructor(
    prefix: ByteArray,
) {
    private class Scratch {
        val state = IntArray(8)
        val w = IntArray(64)
        val block = ByteArray(64)
    }

    private val midstate =
        IntArray(8).also {
            require(prefix.size == 64)
            IV.copyInto(it)
            compress(it, prefix, 0, IntArray(64))
        }

    private val scratch = ScratchLocal { Scratch() }

    actual fun hashInto(
        out: ByteArray,
        buf: ByteArray,
        len: Int,
    ): ByteArray {
        require(len >= 64 && len <= buf.size && out.size >= 32)
        val s = scratch.get()
        val st = s.state
        midstate.copyInto(st)
        var off = 64
        while (len - off >= 64) {
            compress(st, buf, off, s.w)
            off += 64
        }
        // The tail, 0x80, zeros and the 64-bit big-endian bit length of the whole message.
        val block = s.block
        val rem = len - off
        buf.copyInto(block, 0, off, len)
        block[rem] = 0x80.toByte()
        block.fill(0, rem + 1, 64)
        if (rem + 1 > 56) {
            compress(st, block, 0, s.w)
            block.fill(0, 0, 64)
        }
        val bits = len.toLong() * 8
        for (i in 0 until 8) block[56 + i] = (bits ushr (56 - 8 * i)).toByte()
        compress(st, block, 0, s.w)
        for (i in 0 until 8) {
            val v = st[i]
            out[4 * i] = (v ushr 24).toByte()
            out[4 * i + 1] = (v ushr 16).toByte()
            out[4 * i + 2] = (v ushr 8).toByte()
            out[4 * i + 3] = v.toByte()
        }
        return out
    }
}

private val IV =
    intArrayOf(
        0x6a09e667,
        -0x4498517b,
        0x3c6ef372,
        -0x5ab00ac6,
        0x510e527f,
        -0x64fa9774,
        0x1f83d9ab,
        0x5be0cd19,
    )

private val K =
    intArrayOf(
        0x428a2f98,
        0x71374491,
        -0x4a3f0431,
        -0x164a245b,
        0x3956c25b,
        0x59f111f1,
        -0x6dc07d5c,
        -0x54e3a12b,
        -0x27f85568,
        0x12835b01,
        0x243185be,
        0x550c7dc3,
        0x72be5d74,
        -0x7f214e02,
        -0x6423f959,
        -0x3e640e8c,
        -0x1b64963f,
        -0x1041b87a,
        0x0fc19dc6,
        0x240ca1cc,
        0x2de92c6f,
        0x4a7484aa,
        0x5cb0a9dc,
        0x76f988da,
        -0x67c1aeae,
        -0x57ce3993,
        -0x4ffcd838,
        -0x40a68039,
        -0x391ff40d,
        -0x2a586eb9,
        0x06ca6351,
        0x14292967,
        0x27b70a85,
        0x2e1b2138,
        0x4d2c6dfc,
        0x53380d13,
        0x650a7354,
        0x766a0abb,
        -0x7e3d36d2,
        -0x6d8dd37b,
        -0x5d40175f,
        -0x57e599b5,
        -0x3db47490,
        -0x3893ae5d,
        -0x2e6d17e7,
        -0x2966f9dc,
        -0xbf1ca7b,
        0x106aa070,
        0x19a4c116,
        0x1e376c08,
        0x2748774c,
        0x34b0bcb5,
        0x391c0cb3,
        0x4ed8aa4a,
        0x5b9cca4f,
        0x682e6ff3,
        0x748f82ee,
        0x78a5636f,
        -0x7b3787ec,
        -0x7338fdf8,
        -0x6f410006,
        -0x5baf9315,
        -0x41065c09,
        -0x398e870e,
    )

/** One SHA-256 block, block[off, off + 64), into state; w is a 64-word scratch schedule. */
private fun compress(
    state: IntArray,
    block: ByteArray,
    off: Int,
    w: IntArray,
) {
    for (i in 0 until 16) {
        val o = off + 4 * i
        w[i] = (block[o].toInt() shl 24) or ((block[o + 1].toInt() and 0xff) shl 16) or
            ((block[o + 2].toInt() and 0xff) shl 8) or (block[o + 3].toInt() and 0xff)
    }
    for (i in 16 until 64) {
        val x = w[i - 15]
        val y = w[i - 2]
        val s0 = x.rotateRight(7) xor x.rotateRight(18) xor (x ushr 3)
        val s1 = y.rotateRight(17) xor y.rotateRight(19) xor (y ushr 10)
        w[i] = w[i - 16] + s0 + w[i - 7] + s1
    }
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    for (i in 0 until 64) {
        val t1 = h + (e.rotateRight(6) xor e.rotateRight(11) xor e.rotateRight(25)) + ((e and f) xor (e.inv() and g)) + K[i] + w[i]
        val t2 = (a.rotateRight(2) xor a.rotateRight(13) xor a.rotateRight(22)) + ((a and b) xor (a and c) xor (b and c))
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    }
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h
}

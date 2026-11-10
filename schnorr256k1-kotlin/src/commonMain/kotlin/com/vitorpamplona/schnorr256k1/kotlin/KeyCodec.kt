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

// =====================================================================================
// KEY ENCODING, DECODING, AND COORDINATE CONVERSION FOR secp256k1
// =====================================================================================
//
// Converts between public key formats and handles the math for decompressing
// compressed keys (recovering y from x via square root on the curve y² = x³ + 7).
//
// Formats:
//   - x-only (32 bytes): BIP-340 convention, even y assumed
//   - Compressed (33 bytes): 02/03 prefix indicates y parity, followed by x
//   - Uncompressed (65 bytes): 04 prefix, followed by x and y
//   - Jacobian (X, Y, Z): internal projective representation, needs inversion to convert
// =====================================================================================

/**
 * Public key encoding, decoding, and coordinate conversion for secp256k1.
 */
internal object KeyCodec {
    /** Curve constant b = 7 in y² = x³ + 7. */
    private val B = Fe4(7L, 0L, 0L, 0L)

    /** Per thread: [parsePublicKey]'s two temporaries, then [compress]'s x and y. */
    private val scratch = ScratchLocal { Array(4) { Fe4() } }

    /**
     * Lift an x-coordinate to a curve point with even y (BIP-340 convention).
     * Computes y = √(x³ + 7) mod p. Returns false if x is not a valid coordinate.
     */
    fun liftX(
        outX: Fe4,
        outY: Fe4,
        x: Fe4,
    ): Boolean {
        if (U256.cmp(x, FieldP.P) >= 0) return false
        val t = Fe4()
        FieldP.sqr(t, x)
        FieldP.mul(t, t, x)
        FieldP.add(t, t, B) // t = x³ + 7
        if (!FieldP.sqrt(outY, t)) return false
        outX.copyFrom(x)
        if (outY.l0 and 1L != 0L) FieldP.neg(outY, outY) // Ensure even y
        return true
    }

    /** liftX with caller-provided temp buffer (avoids 1 Fe4 alloc). */
    fun liftX(
        outX: Fe4,
        outY: Fe4,
        x: Fe4,
        tmp: Fe4,
    ): Boolean {
        if (U256.cmp(x, FieldP.P) >= 0) return false
        FieldP.sqr(tmp, x)
        FieldP.mul(tmp, tmp, x)
        FieldP.add(tmp, tmp, B)
        if (!FieldP.sqrt(outY, tmp)) return false
        outX.copyFrom(x)
        if (outY.l0 and 1L != 0L) FieldP.neg(outY, outY)
        return true
    }

    /** y mod p is even. y may be unreduced (mul leaves a small y as y + p). */
    fun hasEvenY(y: Fe4): Boolean = !FieldP.isOdd(y)

    /**
     * Parse a serialized public key (33 bytes compressed or 65 bytes uncompressed).
     * For compressed keys (02/03 prefix): decompresses y from x via square root.
     * For uncompressed keys (04 prefix, or the hybrid 06/07): validates the point is on the curve
     * with canonical coordinates, and for a hybrid key that the prefix gives y's parity.
     */
    fun parsePublicKey(
        pubkey: ByteArray,
        outX: Fe4,
        outY: Fe4,
    ): Boolean =
        when (pubkey.size) {
            33 if (pubkey[0] == 0x02.toByte() || pubkey[0] == 0x03.toByte()) -> {
                // Read straight into the outputs: on false the caller ignores them.
                U256.fromBytesInto(outX, pubkey, 1)
                if (U256.cmp(outX, FieldP.P) >= 0) return false
                val t = scratch.get()[0]
                FieldP.sqr(t, outX)
                FieldP.mul(t, t, outX)
                FieldP.add(t, t, B) // y² = x³ + 7
                if (!FieldP.sqrt(outY, t)) return false
                val isOdd = outY.l0 and 1L == 1L
                if (isOdd != (pubkey[0] == 0x03.toByte())) FieldP.neg(outY, outY)
                true
            }

            // 04 || x || y, or a hybrid key (06/07: y's parity in the prefix), as libsecp256k1 parses.
            65 if (pubkey[0] == 0x04.toByte() || pubkey[0] == 0x06.toByte() || pubkey[0] == 0x07.toByte()) -> {
                val x = outX
                val y = outY
                U256.fromBytesInto(x, pubkey, 1)
                U256.fromBytesInto(y, pubkey, 33)
                // Coordinates must be canonical (< p), as libsecp256k1's parser requires.
                if (U256.cmp(x, FieldP.P) >= 0 || U256.cmp(y, FieldP.P) >= 0) return false
                val s = scratch.get()
                val y2 = s[0]
                val x3p7 = s[1]
                FieldP.sqr(y2, y)
                FieldP.sqr(x3p7, x)
                FieldP.mul(x3p7, x3p7, x)
                FieldP.add(x3p7, x3p7, B)
                // Compared reduced: mul, sqr and add leave values below 2^256, not below p, and for
                // a small y (so a small y² and x³ + 7) one side can come back as value + p.
                FieldP.reduceSelf(y2)
                FieldP.reduceSelf(x3p7)
                if (U256.cmp(y2, x3p7) != 0) return false
                if (pubkey[0] != 0x04.toByte() && (y.l0 and 1L == 1L) != (pubkey[0] == 0x07.toByte())) return false
                true
            }

            else -> {
                false
            }
        }

    /**
     * The 33-byte compressed form of a 33- or 65-byte (or hybrid) public key, or null if it is not
     * a point on the curve. A valid key's bytes already are its x, and y's parity is the low bit
     * of its last byte (y is canonical) or its prefix, so the output is copied, not re-encoded:
     * the only allocation is the result.
     */
    fun compress(pubkey: ByteArray): ByteArray? {
        val s = scratch.get()
        if (!parsePublicKey(pubkey, s[2], s[3])) return null
        if (pubkey.size == 33) return pubkey.copyOf()
        val r = ByteArray(33)
        r[0] = if (pubkey[64].toInt() and 1 == 0) 0x02 else 0x03
        pubkey.copyInto(r, 1, 1, 33)
        return r
    }

    /** Serialize as 65-byte uncompressed: 04 || x (32 bytes) || y (32 bytes). */
    fun serializeUncompressed(
        x: Fe4,
        y: Fe4,
    ): ByteArray {
        val r = ByteArray(65)
        r[0] = 0x04
        U256.toBytesInto(x, r, 1)
        U256.toBytesInto(y, r, 33)
        return r
    }

    /** Serialize as 33-byte compressed: 02/03 || x (32 bytes). */
    fun serializeCompressed(
        x: Fe4,
        y: Fe4,
    ): ByteArray {
        val r = ByteArray(33)
        r[0] = if (hasEvenY(y)) 0x02 else 0x03
        U256.toBytesInto(x, r, 1)
        return r
    }
}

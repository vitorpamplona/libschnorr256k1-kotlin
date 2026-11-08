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
 * JVM implementation using Math.multiplyHigh (Java 9+).
 * The HotSpot JIT compiles this to a single hardware instruction:
 * IMULH on x86-64, SMULH on ARM64.
 */
internal actual fun multiplyHigh(
    a: Long,
    b: Long,
): Long = Math.multiplyHigh(a, b)

/**
 * Whether Math.unsignedMultiplyHigh exists (Java 18+). The library targets Java 17, where it does
 * not: calling it there throws NoSuchMethodError. A static final, so the JIT folds the branch in
 * [unsignedMultiplyHigh] away, and the call site of the missing method is never resolved on 17.
 */
private val HAS_UNSIGNED_MULTIPLY_HIGH: Boolean = Runtime.version().feature() >= 18

/**
 * Math.unsignedMultiplyHigh on Java 18+, which the JIT compiles to a single UMULH (or MUL on
 * x86-64); on Java 17, [unsignedMultiplyHighFromSigned].
 *
 * This is the single most performance-critical function in the entire
 * secp256k1 implementation: called 16× per field multiply, ~12,000×
 * per signature verification.
 */
internal actual fun unsignedMultiplyHigh(
    a: Long,
    b: Long,
): Long = if (HAS_UNSIGNED_MULTIPLY_HIGH) Math.unsignedMultiplyHigh(a, b) else unsignedMultiplyHighFromSigned(a, b)

/**
 * The unsigned high product from the signed one (Math.multiplyHigh, Java 9+): reading a negative
 * Long as unsigned adds 2^64 to it, so hi(a·b) gains b when a < 0 and a when b < 0. What
 * Math.unsignedMultiplyHigh itself computes on JDKs without the intrinsic.
 */
internal fun unsignedMultiplyHighFromSigned(
    a: Long,
    b: Long,
): Long = Math.multiplyHigh(a, b) + ((a shr 63) and b) + ((b shr 63) and a)

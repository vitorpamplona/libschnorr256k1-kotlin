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
 * Multiply-high on Kotlin/Native in pure Kotlin (four 32-bit sub-products), for JitPack builds
 * only (JITPACK=true, build.gradle.kts). JitPack builds on Linux, which cannot run the Apple
 * cinterop of the hardware version (src/nativeMulhiCinterop), so its Kotlin/Native klibs use
 * this one: the same results, about 4x the instructions per call. Releases on Maven Central are
 * built on macOS with the hardware version.
 */
internal actual fun multiplyHigh(
    a: Long,
    b: Long,
): Long = multiplyHighFallback(a, b)

internal actual fun unsignedMultiplyHigh(
    a: Long,
    b: Long,
): Long = unsignedMultiplyHighFallback(a, b)

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

import fr.acinq.secp256k1.Secp256k1
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import com.vitorpamplona.schnorr256k1.Schnorr256k1 as CSchnorr256k1

/**
 * The facade must answer exactly like libschnorr256k1-kmp's Schnorr256k1 (the C library), call for
 * call, including null/false on invalid input, so the two are interchangeable.
 */
class Schnorr256k1ApiParityTest {
    private val k = Schnorr256k1
    private val c = CSchnorr256k1
    private val acinq = Secp256k1.get()
    private val r = Random(0xC0DE)

    private fun seckey(): ByteArray {
        while (true) {
            val s = r.nextBytes(32)
            if (c.seckeyVerify(s)) return s
        }
    }

    private fun same(
        what: String,
        a: ByteArray?,
        b: ByteArray?,
    ) {
        if (a == null || b == null) {
            assertEquals(b == null, a == null, "$what: kotlin=${a?.toHexKey()} c=${b?.toHexKey()}")
        } else {
            assertContentEquals(b, a, what)
        }
    }

    @Test
    fun validInputs() {
        repeat(200) {
            val sk = seckey()
            val tweak = seckey()
            val msg = r.nextBytes(if (it % 3 == 0) 32 else r.nextInt(0, 200))
            val aux = r.nextBytes(32)

            val pub = c.pubkeyCreate(sk)!!
            same("pubkeyCreate", k.pubkeyCreate(sk), pub)
            val comp = c.pubkeyCompress(pub)!!
            same("pubkeyCompress", k.pubkeyCompress(pub), comp)
            val xonly = comp.copyOfRange(1, 33)

            val sig = c.schnorrSign(msg, sk, aux)!!
            same("schnorrSign", k.schnorrSign(msg, sk, aux), sig)
            // Not compared with C's schnorrSignXOnly: libschnorr256k1's secp256k1c_schnorr_sign_xonly
            // assumes even y and returns invalid signatures for odd-y keys. Kotlin's must equal
            // the full signature; SignEntryPointsTest checks that on every platform.
            same("schnorrSignXOnly", k.schnorrSignXOnly(msg, sk, xonly, aux), sig)
            same("schnorrSignWithPubKey", k.schnorrSignWithPubKey(msg, sk, comp, aux), sig)
            assertTrue(k.schnorrVerify(sig, msg, xonly))
            assertTrue(k.schnorrVerifyFast(sig, msg, xonly))
            val bad = sig.copyOf().also { b -> b[63] = (b[63] + 1).toByte() }
            assertEquals(c.schnorrVerify(bad, msg, xonly), k.schnorrVerify(bad, msg, xonly))

            same("privkeyTweakAdd", k.privkeyTweakAdd(sk, tweak), c.privkeyTweakAdd(sk, tweak))
            // Refereed by ACINQ, not C: libschnorr256k1's ecmult shares an x-keyed table cache with
            // verify, so after a verify for xonly its tweak-mul of the odd-y key is negated.
            same("pubkeyTweakMul 65", k.pubkeyTweakMul(pub, tweak), acinq.pubKeyTweakMul(pub, tweak))
            same("pubkeyTweakMul 33", k.pubkeyTweakMul(comp, tweak), acinq.pubKeyCompress(acinq.pubKeyTweakMul(comp, tweak)))
            same("ecdhXOnly", k.ecdhXOnly(xonly, tweak), c.ecdhXOnly(xonly, tweak))
            same("sha256", k.sha256(msg), c.sha256(msg))
            same("taggedHash", k.taggedHash("BIP0340/challenge", msg), c.taggedHash("BIP0340/challenge", msg))
        }
    }

    @Test
    fun batchMatches() {
        val sk = seckey()
        val xonly = c.pubkeyCompress(c.pubkeyCreate(sk)!!)!!.copyOfRange(1, 33)
        val msgs = List(16) { r.nextBytes(32) }
        val sigs = msgs.map { c.schnorrSign(it, sk, r.nextBytes(32))!! }
        assertTrue(k.schnorrVerifyBatch(xonly, sigs, msgs))
        assertEquals(c.schnorrVerifyBatch(xonly, sigs, msgs), k.schnorrVerifyBatch(xonly, sigs, msgs))
        val tampered = sigs.toMutableList().also { it[5] = it[5].copyOf().also { b -> b[40] = (b[40] + 1).toByte() } }
        assertFalse(k.schnorrVerifyBatch(xonly, tampered, msgs))
        assertFalse(k.schnorrVerifyBatch(xonly, sigs, msgs.dropLast(1)), "size mismatch is false, not an exception")
    }

    @Test
    fun invalidInputsMatch() {
        val zero = ByteArray(32)
        val n = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".hexToByteArray()
        val short = ByteArray(31) { 1 }
        val sk = seckey()
        val pub = c.pubkeyCreate(sk)!!
        val notOnCurve = ByteArray(32) { 0xFF.toByte() } // x >= p
        for (bad in listOf(zero, n, short)) {
            assertEquals(c.seckeyVerify(bad), k.seckeyVerify(bad), "seckeyVerify")
            same("pubkeyCreate(bad)", k.pubkeyCreate(bad), c.pubkeyCreate(bad))
            same("privkeyTweakAdd(bad tweak)", k.privkeyTweakAdd(sk, bad), c.privkeyTweakAdd(sk, bad))
            same("pubkeyTweakMul(bad tweak)", k.pubkeyTweakMul(pub, bad), c.pubkeyTweakMul(pub, bad))
            same("ecdhXOnly(bad scalar)", k.ecdhXOnly(pub.copyOfRange(1, 33), bad), c.ecdhXOnly(pub.copyOfRange(1, 33), bad))
        }
        same("ecdhXOnly(x >= p)", k.ecdhXOnly(notOnCurve, sk), c.ecdhXOnly(notOnCurve, sk))
        assertEquals(c.schnorrVerify(ByteArray(64), ByteArray(32), notOnCurve), k.schnorrVerify(ByteArray(64), ByteArray(32), notOnCurve))
        assertEquals(
            c.schnorrVerify(ByteArray(63), ByteArray(32), pub.copyOfRange(1, 33)),
            k.schnorrVerify(ByteArray(63), ByteArray(32), pub.copyOfRange(1, 33)),
        )
    }
}

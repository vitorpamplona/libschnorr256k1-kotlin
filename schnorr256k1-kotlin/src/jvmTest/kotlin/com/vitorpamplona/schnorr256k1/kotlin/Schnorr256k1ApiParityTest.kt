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
            same("schnorrSign, null aux", k.schnorrSign(msg, sk, null), c.schnorrSign(msg, sk, null))
            same("schnorrSignXOnly", k.schnorrSignXOnly(msg, sk, xonly, aux), c.schnorrSignXOnly(msg, sk, xonly, aux))
            same("schnorrSignXOnly is schnorrSign", k.schnorrSignXOnly(msg, sk, xonly, aux), sig)
            same("schnorrSignWithPubKey", k.schnorrSignWithPubKey(msg, sk, comp, aux), c.schnorrSignWithPubKey(msg, sk, comp, aux))
            same("schnorrSignWithPubKey is schnorrSign", k.schnorrSignWithPubKey(msg, sk, comp, aux), sig)
            assertTrue(k.schnorrVerify(sig, msg, xonly))
            assertTrue(k.schnorrVerifyFast(sig, msg, xonly))
            val bad = sig.copyOf().also { b -> b[63] = (b[63] + 1).toByte() }
            assertEquals(c.schnorrVerify(bad, msg, xonly), k.schnorrVerify(bad, msg, xonly))

            same("privkeyTweakAdd", k.privkeyTweakAdd(sk, tweak), c.privkeyTweakAdd(sk, tweak))
            // After a verify for xonly, so an x-keyed table cache would show here (1.0.5's did).
            same("pubkeyTweakMul 65", k.pubkeyTweakMul(pub, tweak), c.pubkeyTweakMul(pub, tweak))
            same("pubkeyTweakMul 33", k.pubkeyTweakMul(comp, tweak), c.pubkeyTweakMul(comp, tweak))
            same("pubkeyTweakMul 33, libsecp256k1", k.pubkeyTweakMul(comp, tweak), acinq.pubKeyCompress(acinq.pubKeyTweakMul(comp, tweak)))
            assertTrue(c.schnorrVerify(sig, msg, xonly), "C verify after a tweak-mul of the key")
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

        // s + 1 on one signature and s - 1 on another keep an unweighted batch equation's sum;
        // libschnorr256k1-kmp 1.0.5 accepted them (KI-1). Both must reject them now.
        val one = ByteArray(32).also { it[31] = 1 }
        val minusOne = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140".hexToByteArray()
        val cancelling = sigs.map { it.copyOf() }
        k.privkeyTweakAdd(cancelling[0].copyOfRange(32, 64), one)!!.copyInto(cancelling[0], 32)
        k.privkeyTweakAdd(cancelling[1].copyOfRange(32, 64), minusOne)!!.copyInto(cancelling[1], 32)
        assertFalse(k.schnorrVerifyBatch(xonly, cancelling, msgs))
        assertFalse(c.schnorrVerifyBatch(xonly, cancelling, msgs))
    }

    /** libsecp256k1's answer (ACINQ throws on invalid input), or null. */
    private fun ref(f: () -> ByteArray): ByteArray? =
        try {
            f()
        } catch (_: Exception) {
            null
        }

    /**
     * On invalid input the referee is libsecp256k1, not the C library: libschnorr256k1 answers
     * some of these differently on x86-64 and arm64 (it has an ARM64 assembly field multiply), and
     * where it differs from libsecp256k1 it is the one that is wrong. Kotlin must match
     * libsecp256k1; a difference from C is printed so the platform logs show it.
     */
    private fun refereed(
        what: String,
        kotlin: ByteArray?,
        cLib: ByteArray?,
        libsecp: ByteArray?,
    ) {
        same("$what vs libsecp256k1", kotlin, libsecp)
        val agree = if (kotlin == null || cLib == null) kotlin == cLib else kotlin.contentEquals(cLib)
        if (!agree) println("C DIFFERS ($what, ${System.getProperty("os.arch")}): kotlin=${kotlin?.toHexKey()} c=${cLib?.toHexKey()}")
    }

    @Test
    fun invalidInputsMatchLibsecp256k1() {
        val zero = ByteArray(32)
        val n = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".hexToByteArray()
        val nPlus1 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142".hexToByteArray()
        val short = ByteArray(31) { 1 }
        val sk = seckey()
        val pub = c.pubkeyCreate(sk)!!
        val x = pub.copyOfRange(1, 33)
        val notOnCurve = ByteArray(32) { 0xFF.toByte() } // x >= p
        for (bad in listOf(zero, n, nPlus1, short)) {
            val tag = bad.toHexKey().take(8) + "…/" + bad.size
            assertEquals(acinq.secKeyVerify(bad), k.seckeyVerify(bad), "seckeyVerify($tag)")
            refereed("pubkeyCreate($tag)", k.pubkeyCreate(bad), c.pubkeyCreate(bad), ref { acinq.pubkeyCreate(bad) })
            refereed("privkeyTweakAdd(sk, $tag)", k.privkeyTweakAdd(sk, bad), c.privkeyTweakAdd(sk, bad), ref { acinq.privKeyTweakAdd(sk, bad) })
            refereed("privkeyTweakAdd($tag, sk)", k.privkeyTweakAdd(bad, sk), c.privkeyTweakAdd(bad, sk), ref { acinq.privKeyTweakAdd(bad, sk) })
            refereed("pubkeyTweakMul(pub, $tag)", k.pubkeyTweakMul(pub, bad), c.pubkeyTweakMul(pub, bad), ref { acinq.pubKeyTweakMul(pub, bad) })
            refereed(
                "ecdhXOnly(x, $tag)",
                k.ecdhXOnly(x, bad),
                c.ecdhXOnly(x, bad),
                ref { acinq.pubKeyTweakMul(byteArrayOf(2) + x, bad).copyOfRange(1, 33) },
            )
        }
        refereed(
            "ecdhXOnly(x >= p)",
            k.ecdhXOnly(notOnCurve, sk),
            c.ecdhXOnly(notOnCurve, sk),
            ref { acinq.pubKeyTweakMul(byteArrayOf(2) + notOnCurve, sk).copyOfRange(1, 33) },
        )
        assertFalse(k.schnorrVerify(ByteArray(64), ByteArray(32), notOnCurve))
        assertFalse(k.schnorrVerify(ByteArray(63), ByteArray(32), x))
    }
}

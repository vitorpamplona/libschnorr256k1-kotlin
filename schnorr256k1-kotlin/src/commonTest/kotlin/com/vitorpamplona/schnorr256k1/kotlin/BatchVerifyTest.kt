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

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [Secp256k1.verifySchnorrBatch] must accept exactly the batches whose every signature verifies
 * on its own. The soundness cases are the ones an unweighted sum gets wrong: invalid signatures
 * whose errors cancel, (R1, s1 + d) and (R2, s2 - d), which pass Σs·G == ΣR + (Σe)·P.
 */
class BatchVerifyTest {
    private val rnd = Random(340)

    private fun key(): ByteArray {
        while (true) {
            val k = rnd.nextBytes(32)
            if (Secp256k1.secKeyVerify(k)) return k
        }
    }

    private class Batch(
        val pub: ByteArray,
        val sigs: MutableList<ByteArray>,
        val msgs: List<ByteArray>,
    )

    /** n valid signatures by one key; messages of varying length, as event ids are not all 32 bytes. */
    private fun batch(n: Int): Batch {
        val sec = key()
        val pub = Secp256k1.pubkeyCreate(sec).copyOfRange(1, 33)
        val msgs = List(n) { rnd.nextBytes(if (it % 5 == 4) 64 else 32) }
        val sigs = MutableList(n) { Secp256k1.signSchnorr(msgs[it], sec, rnd.nextBytes(32)) }
        return Batch(pub, sigs, msgs)
    }

    /** sig with s replaced by s + d mod n (d may be negative). */
    private fun shiftS(
        sig: ByteArray,
        d: Long,
    ): ByteArray {
        val s = Fe4()
        U256.fromBytesInto(s, sig, 32)
        val delta = Fe4(if (d >= 0) d else -d, 0, 0, 0)
        val out = if (d >= 0) ScalarN.add(s, delta) else ScalarN.sub(s, delta)
        return sig.copyOfRange(0, 32) + U256.toBytes(out)
    }

    private fun verifiesAlone(b: Batch) = b.sigs.indices.all { Secp256k1.verifySchnorr(b.sigs[it], b.msgs[it], b.pub) }

    @Test
    fun cancellingPairIsRejected() {
        val b = batch(2)
        b.sigs[0] = shiftS(b.sigs[0], 1)
        b.sigs[1] = shiftS(b.sigs[1], -1)
        assertFalse(Secp256k1.verifySchnorr(b.sigs[0], b.msgs[0], b.pub))
        assertFalse(Secp256k1.verifySchnorr(b.sigs[1], b.msgs[1], b.pub))
        assertFalse(Secp256k1.verifySchnorrBatch(b.pub, b.sigs, b.msgs), "two cancelling invalid signatures passed")
    }

    @Test
    fun cancellingPairIsRejectedAnywhereInTheBatch() {
        // Positions on both sides of the chunk boundaries the multi-scalar multiply works in.
        for ((n, i, j) in listOf(Triple(3, 1, 2), Triple(40, 0, 39), Triple(70, 31, 32), Triple(70, 33, 64))) {
            val b = batch(n)
            b.sigs[i] = shiftS(b.sigs[i], 12345)
            b.sigs[j] = shiftS(b.sigs[j], -12345)
            assertFalse(Secp256k1.verifySchnorrBatch(b.pub, b.sigs, b.msgs), "n=$n: cancelling pair at $i, $j passed")
        }
    }

    @Test
    fun cancellingTripleIsRejected() {
        val b = batch(5)
        b.sigs[1] = shiftS(b.sigs[1], 2)
        b.sigs[2] = shiftS(b.sigs[2], -1)
        b.sigs[4] = shiftS(b.sigs[4], -1)
        assertFalse(Secp256k1.verifySchnorrBatch(b.pub, b.sigs, b.msgs))
    }

    @Test
    fun validBatchesOfEverySizeAreAccepted() {
        for (n in (0..70) + listOf(127, 128, 129, 200)) {
            val b = batch(n)
            assertTrue(Secp256k1.verifySchnorrBatch(b.pub, b.sigs, b.msgs), "valid batch of $n rejected")
        }
    }

    @Test
    fun oneInvalidSignatureAnywhereIsRejected() {
        val n = 70
        val base = batch(n)
        for (i in listOf(0, 1, 30, 31, 32, 33, 63, 64, 69)) {
            val sigs = base.sigs.toMutableList()
            sigs[i] = shiftS(sigs[i], 1)
            assertFalse(Secp256k1.verifySchnorrBatch(base.pub, sigs, base.msgs), "invalid signature at $i passed")
        }
    }

    @Test
    fun aSignatureForAnotherMessageIsRejected() {
        val b = batch(10)
        val sigs = b.sigs.toMutableList()
        sigs[3] = b.sigs[4]
        assertFalse(Secp256k1.verifySchnorrBatch(b.pub, sigs, b.msgs))
    }

    @Test
    fun malformedSignaturesAreRejected() {
        // At 0 too: signature 1's R is never lifted, the final check compares with its r instead.
        for (at in listOf(0, 1)) {
            val b = batch(4)
            val p = U256.toBytes(FieldP.P)
            val n = U256.toBytes(ScalarN.N)
            val cases =
                mapOf(
                    "r = p" to p + b.sigs[at].copyOfRange(32, 64),
                    "s = n" to b.sigs[at].copyOfRange(0, 32) + n,
                    "r not an x on the curve" to ByteArray(32).also { it[31] = 5 } + b.sigs[at].copyOfRange(32, 64),
                    "63 bytes" to b.sigs[at].copyOf(63),
                )
            for ((name, bad) in cases) {
                val sigs = b.sigs.toMutableList()
                sigs[at] = bad
                assertFalse(Secp256k1.verifySchnorrBatch(b.pub, sigs, b.msgs), "$name at $at passed")
            }
        }
    }

    /**
     * s' = 2·e·d − s makes s'·G − e·P = −R: the right x, but odd y. A single verify rejects it on
     * R's parity, and so must the batch, also when it is signature 1, whose R the batch never lifts.
     */
    @Test
    fun aSignatureWhoseRHasOddYIsRejected() {
        for (at in listOf(0, 1, 70)) {
            val sec = key()
            val pub65 = Secp256k1.pubkeyCreate(sec)
            val pub = pub65.copyOfRange(1, 33)
            val d = U256.fromBytes(sec).let { if (pub65[64].toInt() and 1 == 1) ScalarN.neg(it) else it }
            val msgs = List(at + 3) { rnd.nextBytes(32) }
            val sigs = MutableList(msgs.size) { Secp256k1.signSchnorr(msgs[it], sec, rnd.nextBytes(32)) }
            val sig = sigs[at]
            val e = ScalarN.reduce(U256.fromBytes(Schnorr256k1.taggedHash("BIP0340/challenge", sig.copyOfRange(0, 32) + pub + msgs[at])!!))
            val twoEd = ScalarN.mul(ScalarN.add(e, e), d)
            val forged = sig.copyOfRange(0, 32) + U256.toBytes(ScalarN.sub(twoEd, U256.fromBytes(sig.copyOfRange(32, 64))))
            assertFalse(Secp256k1.verifySchnorr(forged, msgs[at], pub), "single verify accepted the odd-y R")
            sigs[at] = forged
            assertFalse(Secp256k1.verifySchnorrBatch(pub, sigs, msgs), "batch accepted an odd-y R at $at")
        }
    }

    @Test
    fun agreesWithIndividualVerification() {
        repeat(40) {
            val b = batch(1 + rnd.nextInt(80))
            // Corrupt nothing, one or several signatures, by random amounts.
            repeat(rnd.nextInt(3)) { b.sigs[rnd.nextInt(b.sigs.size)] = shiftS(b.sigs[0], rnd.nextLong(1, 1L shl 40)) }
            assertEquals(verifiesAlone(b), Secp256k1.verifySchnorrBatch(b.pub, b.sigs, b.msgs))
        }
    }
}

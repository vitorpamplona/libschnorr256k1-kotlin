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
        val b = batch(4)
        val p = U256.toBytes(FieldP.P)
        val n = U256.toBytes(ScalarN.N)
        val cases =
            mapOf(
                "r = p" to p + b.sigs[1].copyOfRange(32, 64),
                "s = n" to b.sigs[1].copyOfRange(0, 32) + n,
                "r not an x on the curve" to ByteArray(32).also { it[31] = 5 } + b.sigs[1].copyOfRange(32, 64),
                "63 bytes" to b.sigs[1].copyOf(63),
            )
        for ((name, bad) in cases) {
            val sigs = b.sigs.toMutableList()
            sigs[1] = bad
            assertFalse(Secp256k1.verifySchnorrBatch(b.pub, sigs, b.msgs), "$name passed")
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

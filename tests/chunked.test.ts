import { describe, it, assert, expect } from "vitest"
import { randomBytes } from "@noble/hashes/utils.js"
import { hex } from "@scure/base"
import { aesGCM } from "../lib/aesgcm.js"
import { chunkNonce, chunkOverhead, chunkSize, ciphertextSize, decryptChunks, decryptChunksRandomAccess, encChunkSize, encryptChunks, encryptedChunkCount, plaintextSize } from "../lib/chunked.js"
import { readAll, stream } from "../lib/io.js"
import type { Sliceable } from "../lib/io.js"

const itSlowly = typeof process !== "undefined" && process.env.SLOW ? it : it.skip

const cs = chunkSize
const overhead = chunkOverhead
const maxChunks = 2 ** 38

describe("size functions", function () {
    it.for([
        0, 1, 15, 16, 17, 500,
        cs - 1, cs, cs + 1,
        2 * cs - 1, 2 * cs, 2 * cs + 1, 2 * cs + 500,
    ])("should round-trip plaintext size %s", function (ps) {
        assert.equal(plaintextSize(ciphertextSize(ps)), ps)
    })
    it("should compute the ciphertext size", function () {
        assert.equal(ciphertextSize(0), overhead)
        assert.equal(ciphertextSize(1), 1 + overhead)
        assert.equal(ciphertextSize(cs - 1), cs - 1 + overhead)
        assert.equal(ciphertextSize(cs), cs + 2 * overhead)
        assert.equal(ciphertextSize(cs + 1), cs + 1 + 2 * overhead)
        assert.equal(ciphertextSize(2 * cs), 2 * cs + 3 * overhead)
    })
    it.for([
        -1, -70000, 0, 1, 15,
        NaN, Infinity, 0.5, Number.MAX_SAFE_INTEGER + 1, Number.MAX_VALUE,
    ])("should throw for invalid ciphertext size %s", function (size) {
        expect(() => encryptedChunkCount(size)).to.throw()
        expect(() => plaintextSize(size)).to.throw()
    })
    it.for([-1, NaN, Infinity, 0.5, Number.MAX_SAFE_INTEGER + 1])(
        "should throw for invalid plaintext size %s", function (size) {
            expect(() => ciphertextSize(size)).to.throw()
        })
    it("should reject full final chunks", function () {
        // Spec implementation notes: "any message of encrypted length
        // k * (16 KiB + len(tag)) is truncated"
        for (let k = 1; k <= 3; k++) {
            expect(() => plaintextSize(k * encChunkSize)).to.throw(/invalid encrypted message size/)
        }
    })
    it("should reject final chunks shorter than a tag", function () {
        // Spec: "any message of encrypted length > k * (16 KiB + len(tag))
        // and < k * (16 KiB + len(tag)) + len(tag) is invalid"
        for (let k = 0; k <= 2; k++) {
            for (let delta = 1; delta < overhead; delta++) {
                expect(() => plaintextSize(k * encChunkSize + delta)).to.throw(/invalid encrypted message size/)
            }
        }
    })
    it("should accept the maximum chunk count", function () {
        // Exactly 2³⁸ chunks: (2³⁸ - 1) full chunks + 1 empty final chunk.
        const validSize = (maxChunks - 1) * encChunkSize + overhead
        assert.equal(encryptedChunkCount(validSize), maxChunks)
        const pt = (maxChunks - 1) * cs
        assert.equal(plaintextSize(validSize), pt)
        assert.equal(ciphertextSize(pt), validSize)
        assert.equal(ciphertextSize(pt + cs - 1), validSize + cs - 1)
    })
    it("should reject more than the maximum chunk count", function () {
        const overSize = maxChunks * encChunkSize + overhead
        expect(() => encryptedChunkCount(overSize)).to.throw(/too large/)
        expect(() => plaintextSize(overSize)).to.throw(/too large/)
        expect(() => ciphertextSize(maxChunks * cs)).to.throw(/too large/)
    })
})

describe("chunkNonce", function () {
    const zeros = new Uint8Array(12)
    it("should XOR the chunk index into the final five bytes", function () {
        assert.equal(hex.encode(chunkNonce(zeros, 0)), "000000000000000000000000")
        assert.equal(hex.encode(chunkNonce(zeros, 1)), "000000000000000000000001")
        assert.equal(hex.encode(chunkNonce(zeros, 255)), "0000000000000000000000ff")
        assert.equal(hex.encode(chunkNonce(zeros, 256)), "000000000000000000000100")
        assert.equal(hex.encode(chunkNonce(zeros, 2 ** 32 - 1)), "0000000000000000ffffffff")
        assert.equal(hex.encode(chunkNonce(zeros, 2 ** 32)), "000000000000000100000000")
        assert.equal(hex.encode(chunkNonce(zeros, maxChunks - 1)), "000000000000003fffffffff")
    })
    it("should XOR with the base nonce", function () {
        const base = hex.decode("5f73d9f150410098b2cc408c")
        assert.equal(hex.encode(chunkNonce(base, 0)), "5f73d9f150410098b2cc408c")
        assert.equal(hex.encode(chunkNonce(base, 1)), "5f73d9f150410098b2cc408d")
        assert.equal(hex.encode(chunkNonce(base, 0x1ff)), "5f73d9f150410098b2cc4173")
        assert.equal(hex.encode(chunkNonce(base, 0x40000)), "5f73d9f150410098b2c8408c")
    })
    it("should not modify the base nonce", function () {
        const base = hex.decode("5f73d9f150410098b2cc408c")
        chunkNonce(base, 12345)
        assert.equal(hex.encode(base), "5f73d9f150410098b2cc408c")
    })
    it("should reject chunk indexes past the limit", function () {
        expect(() => chunkNonce(zeros, maxChunks)).to.throw(/counter overflow/)
        expect(() => chunkNonce(zeros, maxChunks + 1)).to.throw(/counter overflow/)
    })
})

async function newAEAD() {
    return { aead: await aesGCM(randomBytes(16)), baseNonce: randomBytes(12) }
}

function chunkedStream(a: Uint8Array, step: number): ReadableStream<Uint8Array> {
    return new ReadableStream<Uint8Array>({
        start(controller) {
            for (let i = 0; i < a.length; i += step) {
                controller.enqueue(a.subarray(i, i + step))
            }
            controller.close()
        }
    })
}

function blob(a: Uint8Array): Blob {
    return new Blob([a as Uint8Array<ArrayBuffer>])
}

async function encrypt(aead: Awaited<ReturnType<typeof newAEAD>>, plaintext: Uint8Array): Promise<Uint8Array> {
    return await readAll(stream(plaintext).pipeThrough(new TransformStream(encryptChunks(aead.aead, aead.baseNonce))))
}

async function decrypt(aead: Awaited<ReturnType<typeof newAEAD>>, ciphertext: Uint8Array): Promise<Uint8Array> {
    return await readAll(stream(ciphertext).pipeThrough(new TransformStream(decryptChunks(aead.aead, aead.baseNonce))))
}

describe("raw mode round trips", function () {
    const lengths = [0, 1000, cs - 1, cs, cs + 1, cs + 100, 2 * cs, 2 * cs + 500]
    const steps = [512, 600, 1000, cs - 1, cs, cs + 1]
    async function testRoundTrip(length: number, step: number) {
        const aead = await newAEAD()
        const src = randomBytes(length)

        const ciphertext = await readAll(chunkedStream(src, step).pipeThrough(new TransformStream(encryptChunks(aead.aead, aead.baseNonce))))
        assert.equal(ciphertext.length, ciphertextSize(length))
        // Raw mode is deterministic.
        assert.deepEqual(await encrypt(aead, src), ciphertext)

        const plaintext = await readAll(chunkedStream(ciphertext, step).pipeThrough(new TransformStream(decryptChunks(aead.aead, aead.baseNonce))))
        assert.deepEqual(plaintext, src)

        const r = await decryptChunksRandomAccess(aead.aead, aead.baseNonce, blob(ciphertext))
        assert.equal(r.size, length)
        assert.deepEqual(await r.bytes(), src)
        assert.deepEqual(await readAll(r.stream()), src)
        for (let off = 0; off < length; off += step) {
            assert.deepEqual(await r.slice(off, off + step).bytes(), src.subarray(off, off + step))
            assert.deepEqual(await readAll(r.slice(off, off + step).stream()), src.subarray(off, off + step))
        }
    }
    it.for(lengths.flatMap(l => steps.map(s => [l, s])))(
        "should round-trip %s bytes in steps of %s", async function ([length, step]) {
            await testRoundTrip(length, step)
        })
    itSlowly("should round-trip byte-by-byte", async function () {
        await testRoundTrip(2 * cs + 500, 1)
    })
})

describe("decryptChunks", function () {
    it("should reject an empty ciphertext", async function () {
        const aead = await newAEAD()
        await expect(decrypt(aead, new Uint8Array(0))).rejects.toThrow(/unexpected EOF/)
    })
    it("should reject a ciphertext ending on a chunk boundary", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, randomBytes(cs))
        assert.equal(ciphertext.length, encChunkSize + overhead)
        await expect(decrypt(aead, ciphertext.subarray(0, encChunkSize))).rejects.toThrow(/unexpected EOF/)
    })
    it("should reject a final chunk shorter than a tag", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, randomBytes(cs + 100))
        for (const n of [1, 15]) {
            await expect(decrypt(aead, ciphertext.subarray(0, encChunkSize + n))).rejects.toThrow()
        }
    })
    it("should reject a modified ciphertext", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, randomBytes(cs + 100))
        for (const i of [0, encChunkSize - 1, encChunkSize, ciphertext.length - 1]) {
            const modified = ciphertext.slice()
            modified[i] ^= 0x01
            await expect(decrypt(aead, modified)).rejects.toThrow(/authentication failed/)
        }
    })
    it("should reject trailing data", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, randomBytes(100))
        const extended = new Uint8Array(ciphertext.length + 20)
        extended.set(ciphertext)
        await expect(decrypt(aead, extended)).rejects.toThrow(/authentication failed/)
    })
    it("should reject a different base nonce or key", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, randomBytes(100))
        const other = await newAEAD()
        await expect(decrypt({ aead: aead.aead, baseNonce: other.baseNonce }, ciphertext)).rejects.toThrow(/authentication failed/)
        await expect(decrypt({ aead: other.aead, baseNonce: aead.baseNonce }, ciphertext)).rejects.toThrow(/authentication failed/)
    })
    it("should reject invalid base nonces", async function () {
        const aead = await newAEAD()
        expect(() => encryptChunks(aead.aead, new Uint8Array(11))).to.throw(/base nonce/)
        expect(() => decryptChunks(aead.aead, new Uint8Array(13))).to.throw(/base nonce/)
        await expect(decryptChunksRandomAccess(aead.aead, new Uint8Array(0), blob(new Uint8Array(16)))).rejects.toThrow(/base nonce/)
    })
})

describe("transform streams", function () {
    const tick = () => new Promise((resolve) => setTimeout(resolve, 10))

    it("should propagate cancellation to the writer", async function () {
        const { aead, baseNonce } = await newAEAD()
        const { readable, writable } = new TransformStream(encryptChunks(aead, baseNonce))
        const writer = writable.getWriter()
        await readable.cancel(Error("consumer went away"))
        await tick()
        await expect(writer.write(randomBytes(10))).rejects.toThrow()
        await expect(writer.close()).rejects.toThrow()
    })
    it("should propagate producer errors to the reader", async function () {
        const { aead, baseNonce } = await newAEAD()
        const { readable, writable } = new TransformStream(encryptChunks(aead, baseNonce))
        const reading = readAll(readable)
        const writer = writable.getWriter()
        await writer.abort(Error("producer failed"))
        await expect(reading).rejects.toThrow(/producer failed/)
    })
    it("should propagate transform errors to the writer", async function () {
        const { aead, baseNonce } = await newAEAD()
        const { readable, writable } = new TransformStream(decryptChunks(aead, baseNonce))
        const reading = readAll(readable)
        const writer = writable.getWriter()
        await expect(writer.write(new Uint8Array(encChunkSize))).rejects.toThrow(/authentication failed/)
        await expect(reading).rejects.toThrow(/authentication failed/)
        await expect(writer.write(randomBytes(10))).rejects.toThrow()
    })
})

class TrackingSliceable implements Sliceable {
    called = false
    private inner: Sliceable
    constructor(inner: Sliceable) {
        this.inner = inner
    }
    get size(): number {
        return this.inner.size
    }
    slice(start: number, end: number): { arrayBuffer(): Promise<ArrayBuffer> } {
        this.called = true
        return this.inner.slice(start, end)
    }
}

describe("decryptChunksRandomAccess", function () {
    it("should decrypt chunks on demand and cache the last one", async function () {
        const aead = await newAEAD()
        // Plaintext spanning exactly 3 chunks: 2 full chunks + partial third.
        const size = 2 * cs + 500
        const plaintext = randomBytes(size)
        const ciphertext = await encrypt(aead, plaintext)

        const tracker = new TrackingSliceable(blob(ciphertext))
        const r = await decryptChunksRandomAccess(aead.aead, aead.baseNonce, tracker)
        assert.equal(r.size, size)
        assert.isTrue(tracker.called)

        const checkRead = async (name: string, off: number, length: number, wantN: number, wantSrcRead: boolean) => {
            tracker.called = false
            const got = await r.slice(off, off + length).bytes()
            assert.equal(got.length, wantN, name + ": length")
            assert.deepEqual(got, plaintext.subarray(off, off + wantN), name + ": data")
            assert.equal(tracker.called, wantSrcRead, name + ": source read")
        }

        await checkRead("final chunk (cached by constructor)", 2 * cs + 100, 100, 100, false)
        await checkRead("span chunks 1-2", cs + cs - 50, 100, 100, true)
        await checkRead("final chunk after span", 2 * cs + 200, 100, 100, false)
        await checkRead("final chunk (cached again)", 2 * cs + 50, 50, 50, false)
        await checkRead("first chunk", 0, 100, 100, true)
        await checkRead("first chunk (cached)", 50, 100, 100, false)
        await checkRead("span all", 0, size, size, true)
        await checkRead("beyond end", size + 100, 100, 0, false)
        await checkRead("offset = size", size, 100, 0, false)
        await checkRead("span last and beyond", 2 * cs + 400, 1000, 100, false)
        await checkRead("span second and last and beyond", cs + 100, cs + 1000, size - (cs + 100), true)
        // Blob.slice semantics.
        assert.deepEqual(await r.slice(-100).bytes(), plaintext.subarray(size - 100), "negative start")
        assert.deepEqual(await r.slice(-size - 100, 10).bytes(), plaintext.subarray(0, 10), "negative start before the beginning")
        assert.deepEqual(await r.slice(100, -100).bytes(), plaintext.subarray(100, size - 100), "negative end")
        assert.deepEqual(await r.slice(10, 5).bytes(), new Uint8Array(0), "end before start")
        // Fractions are rounded to the nearest integer, ties to even, like
        // the Web IDL [Clamp] long long type.
        assert.deepEqual(await r.slice(0.9, 2.1).bytes(), plaintext.subarray(1, 2), "fractional indexes")
        assert.deepEqual(await r.slice(1.5, 2.5).bytes(), new Uint8Array(0), "fractional indexes with ties")
        assert.deepEqual(await r.slice(0.5, 3.5).bytes(), plaintext.subarray(0, 4), "fractional indexes with ties")
        assert.deepEqual(await r.slice(NaN, Infinity).bytes(), plaintext, "NaN and Infinity")
        assert.deepEqual(await r.slice(-Infinity, 5).bytes(), plaintext.subarray(0, 5), "negative Infinity")
        // Non-numbers are converted like by Web IDL, for untyped callers.
        assert.deepEqual(await r.slice("abc" as unknown as number).bytes(), plaintext, "non-numeric start")
        assert.deepEqual(await r.slice({} as unknown as number, 5).bytes(), plaintext.subarray(0, 5), "non-numeric start with end")
        assert.deepEqual(await r.slice("1" as unknown as number, "3" as unknown as number).bytes(), plaintext.subarray(1, 3), "numeric strings")
        assert.deepEqual(await r.slice(null as unknown as number, true as unknown as number).bytes(), plaintext.subarray(0, 1), "null and true")
        assert.throws(() => r.slice(1n as unknown as number), TypeError, undefined, "BigInt")
        await checkRead("zero-length in the middle", 100, 0, 0, false)
        await checkRead("zero-length at end", size, 0, 0, false)
        await checkRead("exact chunk at boundary", cs, cs, cs, true)
        await checkRead("one byte at start", 0, 1, 1, true)
        await checkRead("one byte at cs-1", cs - 1, 1, 1, false)
        await checkRead("one byte at cs", cs, 1, 1, true)
        await checkRead("one byte at 2*cs-1", 2 * cs - 1, 1, 1, false)
        await checkRead("one byte at 2*cs", 2 * cs, 1, 1, true)
        await checkRead("last byte", size - 1, 1, 1, false)
        await checkRead("cross boundary 0-1", cs - 50, 100, 100, true)
        await checkRead("cross boundary 1-2", 2 * cs - 50, 100, 100, true)
    })
    it("should slice like a Blob", async function () {
        const aead = await newAEAD()
        const plaintext = randomBytes(2 * cs + 500)
        const native = blob(plaintext)
        const r = await decryptChunksRandomAccess(aead.aead, aead.baseNonce, blob(await encrypt(aead, plaintext)))
        // Runtimes disagree on the conversion of fractional and infinite
        // indexes, so only integers are compared with the native Blob.
        const ranges: [number?, number?][] = [
            [], [0], [5], [-1], [-5, -1], [0, 1], [1, 1], [2, 1], [-1, -2], [0, 100000], [100000], [-100000, 2],
            [cs], [cs, 2 * cs], [-500], [plaintext.length], [plaintext.length, plaintext.length + 1],
            [-plaintext.length], [-plaintext.length - 1, 1], [0, -plaintext.length],
        ]
        for (const [start, end] of ranges) {
            const want = new Uint8Array(await native.slice(start, end).arrayBuffer())
            assert.equal(r.slice(start, end).size, want.length, JSON.stringify([start, end]))
            assert.deepEqual(await r.slice(start, end).bytes(), want, JSON.stringify([start, end]))
            assert.deepEqual(await readAll(r.slice(start, end).stream()), want, JSON.stringify([start, end]))
        }
    })
    it("should decrypt an empty message", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, new Uint8Array(0))
        const tracker = new TrackingSliceable(blob(ciphertext))
        const r = await decryptChunksRandomAccess(aead.aead, aead.baseNonce, tracker)
        tracker.called = false
        assert.equal(r.size, 0)
        assert.deepEqual(await r.bytes(), new Uint8Array(0))
        assert.deepEqual(await r.slice(0, 100).bytes(), new Uint8Array(0))
        assert.deepEqual(await r.slice(1, 100).bytes(), new Uint8Array(0))
        assert.deepEqual(await r.slice(-1).bytes(), new Uint8Array(0))
        assert.isFalse(tracker.called)
    })
    it("should serve a single chunk from the cache", async function () {
        const aead = await newAEAD()
        const plaintext = randomBytes(1000)
        const ciphertext = await encrypt(aead, plaintext)
        const tracker = new TrackingSliceable(blob(ciphertext))
        const r = await decryptChunksRandomAccess(aead.aead, aead.baseNonce, tracker)
        tracker.called = false
        assert.deepEqual(await r.slice(0, 100).bytes(), plaintext.subarray(0, 100))
        assert.deepEqual(await r.slice(900, 1000).bytes(), plaintext.subarray(900))
        assert.deepEqual(await r.slice(900, 1100).bytes(), plaintext.subarray(900))
        assert.isFalse(tracker.called)
    })
    it("should decrypt a message of full chunks", async function () {
        const aead = await newAEAD()
        const plaintext = randomBytes(2 * cs)
        const ciphertext = await encrypt(aead, plaintext)
        const r = await decryptChunksRandomAccess(aead.aead, aead.baseNonce, blob(ciphertext))
        assert.equal(r.size, 2 * cs)
        assert.deepEqual(await r.slice(2 * cs - 1, 2 * cs).bytes(), plaintext.subarray(2 * cs - 1))
        assert.deepEqual(await r.slice(cs - 50, cs + 50).bytes(), plaintext.subarray(cs - 50, cs + 50))
        assert.deepEqual(await r.slice(2 * cs, 2 * cs + 1).bytes(), new Uint8Array(0))
    })
    it("should reject a wrong key or base nonce", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, randomBytes(1000))
        const other = await newAEAD()
        await expect(decryptChunksRandomAccess(other.aead, aead.baseNonce, blob(ciphertext))).rejects.toThrow(/authentication failed/)
        await expect(decryptChunksRandomAccess(aead.aead, other.baseNonce, blob(ciphertext))).rejects.toThrow(/authentication failed/)
    })
    it("should reject a wrong size", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, randomBytes(1000))
        const src = blob(ciphertext)
        const lying = (size: number) => ({ size, slice: (start: number, end: number) => src.slice(start, end) })
        // One byte less is the size of a valid 999-byte message, but the
        // final chunk doesn't authenticate.
        await expect(decryptChunksRandomAccess(aead.aead, aead.baseNonce, lying(ciphertext.length - 1))).rejects.toThrow(/authentication failed/)
        // One byte more is the size of a valid 1001-byte message, but the
        // source is too short.
        await expect(decryptChunksRandomAccess(aead.aead, aead.baseNonce, lying(ciphertext.length + 1))).rejects.toThrow(/unexpected EOF/)
        for (const size of [0, 1, 15, encChunkSize, encChunkSize + 1, -1, 0.5, NaN]) {
            await expect(decryptChunksRandomAccess(aead.aead, aead.baseNonce, lying(size)), size.toString()).rejects.toThrow(/invalid encrypted message size/)
        }
    })
    it("should reject a source shorter than its size", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, randomBytes(2 * cs + 500))
        const truncated = blob(ciphertext.subarray(0, ciphertext.length - 100))
        const lying = { size: ciphertext.length, slice: (start: number, end: number) => truncated.slice(start, end) }
        await expect(decryptChunksRandomAccess(aead.aead, aead.baseNonce, lying)).rejects.toThrow(/unexpected EOF/)
    })
    it("should reject a source longer than its size", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, randomBytes(2 * cs + 500))
        const src = blob(ciphertext)
        const lying = { size: ciphertext.length, slice: (start: number, end: number) => src.slice(start, end + 1) }
        // The final chunk read is clamped by Blob.slice, but the others aren't.
        const r = await decryptChunksRandomAccess(aead.aead, aead.baseNonce, lying)
        await expect(r.slice(0, 10).bytes()).rejects.toThrow(/unexpected data/)
    })
    it("should reject a message truncated to a full final chunk", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, randomBytes(3 * cs + 500))
        const truncated = ciphertext.subarray(0, 3 * encChunkSize)
        await expect(decryptChunksRandomAccess(aead.aead, aead.baseNonce, blob(truncated))).rejects.toThrow(/invalid encrypted message size/)
    })
    it("should reject an oversized message without reading it", async function () {
        const aead = await newAEAD()
        const src = { size: maxChunks * encChunkSize + overhead, slice: () => ({ arrayBuffer: () => Promise.reject(Error("should not be called")) }) }
        await expect(decryptChunksRandomAccess(aead.aead, aead.baseNonce, src)).rejects.toThrow(/too large/)
    })
    it("should reject corrupted chunks", async function () {
        const aead = await newAEAD()
        const ciphertext = await encrypt(aead, randomBytes(2 * cs + 500))

        // Corrupt the final chunk: it fails during construction.
        const corruptedFinal = ciphertext.slice()
        corruptedFinal[corruptedFinal.length - 10] ^= 0xff
        await expect(decryptChunksRandomAccess(aead.aead, aead.baseNonce, blob(corruptedFinal))).rejects.toThrow(/authentication failed/)

        // Corrupt the first chunk: it fails when read.
        const corruptedFirst = ciphertext.slice()
        corruptedFirst[10] ^= 0xff
        const r = await decryptChunksRandomAccess(aead.aead, aead.baseNonce, blob(corruptedFirst))
        await expect(r.slice(0, 100).bytes()).rejects.toThrow(/authentication failed/)
        await expect(r.slice(cs - 1, cs + 1).bytes()).rejects.toThrow(/authentication failed/)
        assert.equal((await r.slice(cs, cs + 100).bytes()).length, 100)
        await expect(readAll(r.stream())).rejects.toThrow(/authentication failed/)
        assert.equal((await readAll(r.slice(cs).stream())).length, cs + 500)
    })
})

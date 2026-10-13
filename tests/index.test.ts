import { describe, it, assert, expect, onTestFinished } from "vitest"
import { randomBytes } from "@noble/hashes/utils.js"
import { sha256 } from "@noble/hashes/sha2.js"
import { hex } from "@scure/base"
import { Decrypter, DecryptionStream, Encrypter, EncryptionStream, ciphertextSize, generateKey, keySize, plaintextSize } from "../lib/index.js"
import type { DecryptedBlob, Sliceable } from "../lib/index.js"
import { forceWebCryptoOff } from "../lib/aesgcm.js"
import { chunkOverhead, chunkSize } from "../lib/chunked.js"
import { flatten, readAll, stream } from "../lib/io.js"

const cs = chunkSize
const overhead = chunkOverhead
const encChunkSize = cs + overhead
const headerSize = 56

const knownKey = hex.decode("000102030405060708090a0b0c0d0e0f")

describe("Decrypter", function () {
    it("should decrypt a message encrypted by filippo.io/cobblestone", async function () {
        const d = new Decrypter(knownKey, "test context")
        const ciphertext = hex.decode("000a8e00889fd6ccb82f5734d8f752e8e884708a10acb399d739858e247eaf8ff3fce6fb683e9e26be836f6f0ec67120bfa07de9469082795e6e8b529c5a7336b3ecef0c40bccbb96e48b76326703af8f712c462afa2a93330495b")
        assert.equal(text(await d.decrypt(ciphertext)), "Hello, Cobblestone!")
    })
    it("should decrypt a message encrypted by pyca/cryptography", async function () {
        const d = new Decrypter(knownKey, "test context")
        const ciphertext = hex.decode("7e0fa5facaa2eabd274a457bb1fd1c81c1a018ae363dc575605a743622e39f2fc134436e256dcb4249ff3c714d936a66e09f338c5fa3b51a5d66eda09ad4d6ab1227ecc7276c89ae6772b75fa84c4b0ecd89ce1f7df2f226e54ab0")
        assert.equal(text(await d.decrypt(ciphertext)), "Hello, Cobblestone!")
        assert.deepEqual(await d.decrypt(ciphertext), new TextEncoder().encode("Hello, Cobblestone!"))
    })
    it("should decrypt a known message via streaming", async function () {
        const ciphertext = hex.decode("7e0fa5facaa2eabd274a457bb1fd1c81c1a018ae363dc575605a743622e39f2fc134436e256dcb4249ff3c714d936a66e09f338c5fa3b51a5d66eda09ad4d6ab1227ecc7276c89ae6772b75fa84c4b0ecd89ce1f7df2f226e54ab0")
        const out = stream(ciphertext).pipeThrough(new DecryptionStream(knownKey, "test context"))
        assert.equal(await new Response(out).text(), "Hello, Cobblestone!")
    })
    it("should decrypt a known message via random access", async function () {
        const d = new Decrypter(knownKey, "test context")
        const ciphertext = hex.decode("7e0fa5facaa2eabd274a457bb1fd1c81c1a018ae363dc575605a743622e39f2fc134436e256dcb4249ff3c714d936a66e09f338c5fa3b51a5d66eda09ad4d6ab1227ecc7276c89ae6772b75fa84c4b0ecd89ce1f7df2f226e54ab0")
        const r = await d.decryptBlob(blob(ciphertext))
        assert.equal(r.size, "Hello, Cobblestone!".length)
        assert.equal(text(await r.slice(7, 18).bytes()), "Cobblestone")
    })
})

describe("key generation", function () {
    it("should generate random keys", function () {
        const key = generateKey()
        assert.equal(key.length, keySize)
        assert.equal(key.length, 16)
        assert.notDeepEqual(key, generateKey())
    })
    it("should encrypt and decrypt a message", async function () {
        const key = generateKey()
        const e = new Encrypter(key)
        const ciphertext = await e.encrypt(bytes("cobblestone"))
        const d = new Decrypter(key)
        assert.equal(text(await d.decrypt(ciphertext)), "cobblestone")
    })
})

describe("Encrypter", function () {
    it("should encrypt (and decrypt) a message with a context", async function () {
        const key = generateKey()
        const e = new Encrypter(key, "test context")
        const ciphertext = await e.encrypt(bytes("cobblestone"))
        assert.equal(ciphertext.length, ciphertextSize("cobblestone".length))
        assert.equal(ciphertext.length, headerSize + "cobblestone".length + overhead)
        const d = new Decrypter(key, "test context")
        assert.equal(text(await d.decrypt(ciphertext)), "cobblestone")
    })
    it("should encrypt (and decrypt) a message with a binary context", async function () {
        const key = generateKey()
        const e = new Encrypter(key, new Uint8Array([0x74, 0x65, 0x73, 0x74, 0x00, 0xff]))
        const ciphertext = await e.encrypt(bytes("cobblestone"))
        const d = new Decrypter(key, new Uint8Array([0x74, 0x65, 0x73, 0x74, 0x00, 0xff]))
        assert.equal(text(await d.decrypt(ciphertext)), "cobblestone")
    })
    it("should encode string contexts as UTF-8", async function () {
        const key = generateKey()
        const e = new Encrypter(key, "contesto 🪨")
        const ciphertext = await e.encrypt(bytes("cobblestone"))
        const d = new Decrypter(key, new TextEncoder().encode("contesto 🪨"))
        assert.equal(text(await d.decrypt(ciphertext)), "cobblestone")
    })
    it("should treat a missing context as empty", async function () {
        const key = generateKey()
        const e = new Encrypter(key)
        const ciphertext = await e.encrypt(bytes("cobblestone"))
        assert.equal(text(await new Decrypter(key, "").decrypt(ciphertext)), "cobblestone")
        assert.equal(text(await new Decrypter(key, new Uint8Array(0)).decrypt(ciphertext)), "cobblestone")
    })
    it("should encrypt multiple messages with different salts", async function () {
        const key = generateKey()
        const e = new Encrypter(key, "ctx")
        const a = await e.encrypt(bytes("same message"))
        const b = await e.encrypt(bytes("same message"))
        assert.notDeepEqual(a.subarray(0, 24), b.subarray(0, 24))
        assert.notDeepEqual(a, b)
        const d = new Decrypter(key, "ctx")
        assert.equal(text(await d.decrypt(a)), "same message")
        assert.equal(text(await d.decrypt(b)), "same message")
    })
    it("should not be affected by later changes to the key or context", async function () {
        const key = generateKey()
        const context = new TextEncoder().encode("ctx")
        const e = new Encrypter(key, context)
        const d = new Decrypter(key, context)
        key[0] ^= 0xff
        context[0] ^= 0xff
        assert.equal(text(await d.decrypt(await e.encrypt(bytes("cobblestone")))), "cobblestone")
    })
    it.for([
        [0, 1], [1, 1],
        [cs - 1, 100], [cs - 1, 128],
        [cs, 100], [cs, 128],
        [cs + 1, 100], [cs + 1, 128],
        [2 * cs - 1, 100], [2 * cs - 1, 128],
        [2 * cs, 100], [2 * cs, 128],
        [2 * cs + 1, 100], [2 * cs + 1, 128],
        [2 * cs + 500, cs], [2 * cs + 500, cs + 1], [2 * cs + 500, encChunkSize],
    ])("should encrypt (and decrypt) a message of %s bytes with ReadableStream chunks of %s", async function ([size, chunk]) {
        const key = generateKey()

        const source = randomBytesStream(size, chunk)
        const sourceHash = new HashingTransformStream()
        const encrypted = source.pipeThrough(sourceHash).pipeThrough(new EncryptionStream(key, "ctx"))
        const encryptedSize = new SizeTransformStream()
        const decrypted = encrypted.pipeThrough(encryptedSize).pipeThrough(rechunk(chunk)).pipeThrough(new DecryptionStream(key, "ctx"))
        const decryptedHash = new HashingTransformStream()
        const plaintext = await readAll(decrypted.pipeThrough(decryptedHash))
        assert.equal(plaintext.length, size)
        assert.equal(encryptedSize.size, ciphertextSize(size))
        assert.equal(plaintextSize(encryptedSize.size), size)
        assert.deepEqual(sourceHash.digest, decryptedHash.digest)
    })
    it("should encrypt (and decrypt) without Web Crypto", async function () {
        withoutWebCrypto()
        const key = generateKey()
        const e = new Encrypter(key, "ctx")
        const ciphertext = await e.encrypt(randomBytes(cs + 100))
        const d = new Decrypter(key, "ctx")
        const plaintext = await d.decrypt(ciphertext)
        assert.equal(plaintext.length, cs + 100)
    })
    it("should interoperate with and without Web Crypto", async function () {
        const key = generateKey()
        const plaintext = randomBytes(cs + 100)
        const e = new Encrypter(key, "ctx")
        const d = new Decrypter(key, "ctx")

        const withWebCrypto = await e.encrypt(plaintext)
        forceWebCryptoOff(true)
        onTestFinished(() => { forceWebCryptoOff(false) })
        assert.deepEqual(await d.decrypt(withWebCrypto), plaintext)
        const withoutWebCrypto = await e.encrypt(plaintext)
        forceWebCryptoOff(false)
        assert.deepEqual(await d.decrypt(withoutWebCrypto), plaintext)
    })
    it("should throw when using bad keys", function () {
        for (const size of [0, 1, 15, 17, 32]) {
            assert.throws(() => new Encrypter(new Uint8Array(size)), /invalid key size/)
            assert.throws(() => new Decrypter(new Uint8Array(size)), /invalid key size/)
            assert.throws(() => new EncryptionStream(new Uint8Array(size)), /invalid key size/)
            assert.throws(() => new DecryptionStream(new Uint8Array(size)), /invalid key size/)
        }
        // @ts-expect-error testing invalid input
        assert.throws(() => new Encrypter("0001020304050607080a0b0c0d0e0f"), /Uint8Array/)
        // @ts-expect-error testing invalid input
        assert.throws(() => new Decrypter([...knownKey]), /Uint8Array/)
    })
    it("should reject inputs that are not Uint8Arrays", async function () {
        const key = generateKey()
        const notBytes = "cobblestone" as unknown as Uint8Array
        await expect(new Encrypter(key).encrypt(notBytes)).rejects.toThrow(/Uint8Array/)
        await expect(new Decrypter(key).decrypt(notBytes)).rejects.toThrow(/Uint8Array/)
        await expect(readAll(stream(notBytes).pipeThrough(new EncryptionStream(key)))).rejects.toThrow(/Uint8Array/)
        await expect(readAll(stream(notBytes).pipeThrough(new DecryptionStream(key)))).rejects.toThrow(/Uint8Array/)
        // @ts-expect-error testing invalid input
        assert.throws(() => new Encrypter(key, 42), /Uint8Array/)
    })
})

describe("Decrypter errors", function () {
    it("should reject a wrong key", async function () {
        const ciphertext = await new Encrypter(generateKey(), "ctx").encrypt(bytes("cobblestone"))
        const wrongKey = generateKey()
        const d = new Decrypter(wrongKey, "ctx")
        await expect(d.decrypt(ciphertext)).rejects.toThrow(/invalid commitment/)
        await expect(decryptStream(wrongKey, "ctx", ciphertext)).rejects.toThrow(/invalid commitment/)
        await expect(d.decryptBlob(blob(ciphertext))).rejects.toThrow(/invalid commitment/)
    })
    it("should reject a wrong context", async function () {
        const key = generateKey()
        const ciphertext = await new Encrypter(key, "context-A").encrypt(bytes("cobblestone"))
        for (const context of ["context-B", "", "context-A "]) {
            const d = new Decrypter(key, context)
            await expect(d.decrypt(ciphertext)).rejects.toThrow(/invalid commitment/)
            await expect(decryptStream(key, context, ciphertext)).rejects.toThrow(/invalid commitment/)
            await expect(d.decryptBlob(blob(ciphertext))).rejects.toThrow(/invalid commitment/)
        }
    })
    it.for([
        ["salt", 0],
        ["commitment", 24],
        ["first chunk", headerSize],
        ["first tag", headerSize + encChunkSize - 1],
        ["final chunk", headerSize + encChunkSize + 3],
        ["final tag", headerSize + encChunkSize + 100 + overhead - 1],
    ])("should reject a modified %s", async function ([name, position]) {
        const key = generateKey()
        const ciphertext = await new Encrypter(key, "ctx").encrypt(randomBytes(cs + 100))
        ciphertext[position as number] ^= 0x01
        const d = new Decrypter(key, "ctx")
        await expect(d.decrypt(ciphertext), name as string).rejects.toThrow()
        await expect(decryptStream(key, "ctx", ciphertext), name as string).rejects.toThrow()
        await expect(sliceOrFail(d.decryptBlob(blob(ciphertext))), name as string).rejects.toThrow()
    })
    it("should reject a message with swapped chunks", async function () {
        const key = generateKey()
        const ciphertext = await new Encrypter(key, "ctx").encrypt(randomBytes(2 * cs + 100))
        const chunk0 = ciphertext.subarray(headerSize, headerSize + encChunkSize)
        const chunk1 = ciphertext.subarray(headerSize + encChunkSize, headerSize + 2 * encChunkSize)
        const swapped = ciphertext.slice()
        swapped.set(chunk1, headerSize)
        swapped.set(chunk0, headerSize + encChunkSize)
        const d = new Decrypter(key, "ctx")
        await expect(d.decrypt(swapped)).rejects.toThrow(/authentication failed/)
    })
    it.for([
        0, 1, headerSize - 1,
        headerSize, // no final chunk at all
        headerSize + overhead - 1, // final chunk shorter than its tag
        headerSize + encChunkSize, // ends on a chunk boundary
        headerSize + encChunkSize + overhead - 1,
    ])("should reject a message truncated to %s bytes", async function (length) {
        const key = generateKey()
        const ciphertext = await new Encrypter(key, "ctx").encrypt(randomBytes(cs + 100))
        const truncated = ciphertext.subarray(0, length)
        const d = new Decrypter(key, "ctx")
        await expect(d.decrypt(truncated)).rejects.toThrow()
        await expect(decryptStream(key, "ctx", truncated)).rejects.toThrow()
        await expect(sliceOrFail(d.decryptBlob(blob(truncated)))).rejects.toThrow()
        if (length < headerSize) {
            await expect(d.decrypt(truncated)).rejects.toThrow(/unexpected EOF/)
            await expect(d.decryptBlob(blob(truncated))).rejects.toThrow(/input too short/)
            assert.throws(() => plaintextSize(length), /input too short/)
        } else {
            assert.throws(() => plaintextSize(length), /invalid encrypted message size/)
        }
    })
    it("should reject a message with trailing data", async function () {
        const key = generateKey()
        const ciphertext = await new Encrypter(key, "ctx").encrypt(bytes("cobblestone"))
        const extended = new Uint8Array(ciphertext.length + 20)
        extended.set(ciphertext)
        const d = new Decrypter(key, "ctx")
        await expect(d.decrypt(extended)).rejects.toThrow(/authentication failed/)
        await expect(decryptStream(key, "ctx", extended)).rejects.toThrow(/authentication failed/)
        await expect(d.decryptBlob(blob(extended))).rejects.toThrow(/authentication failed/)
    })
    it("should produce only authenticated chunks when streaming", async function () {
        const key = generateKey()
        const plaintext = randomBytes(3 * cs + 100)
        const ciphertext = await new Encrypter(key, "ctx").encrypt(plaintext)
        ciphertext[headerSize + 2 * encChunkSize] ^= 0x01 // corrupt the third chunk
        const reader = stream(ciphertext).pipeThrough(rechunk(1000)).pipeThrough(new DecryptionStream(key, "ctx")).getReader()
        const chunks: Uint8Array<ArrayBuffer>[] = []
        let error: unknown = null
        for (; ;) {
            try {
                const { done, value } = await reader.read()
                if (done) break
                chunks.push(value)
            } catch (e) {
                error = e
                break
            }
        }
        assert.instanceOf(error, Error)
        assert.match(error.message, /authentication failed/)
        await expect(reader.read()).rejects.toThrow(/authentication failed/)
        const got = await readAll(new Blob(chunks).stream())
        assert.deepEqual(got, plaintext.subarray(0, 2 * cs))
    })
    it("should fail without Web Crypto", async function () {
        withoutWebCrypto()
        const key = generateKey()
        const ciphertext = await new Encrypter(key, "ctx").encrypt(randomBytes(cs + 100))
        ciphertext[headerSize + encChunkSize + 3] ^= 0x01
        const d = new Decrypter(key, "ctx")
        await expect(d.decrypt(ciphertext)).rejects.toThrow(/authentication failed/)
        await expect(new Decrypter(key, "other").decrypt(ciphertext)).rejects.toThrow(/invalid commitment/)
    })
})

describe("output buffers", function () {
    // checkOwned checks that a value returned by the library is a view of its
    // whole underlying buffer, so that it doesn't expose any other data (e.g.
    // key material) through it.
    function checkOwned(a: Uint8Array, name: string) {
        assert.equal(a.byteOffset, 0, name + ": byteOffset")
        assert.equal(a.buffer.byteLength, a.byteLength, name + ": buffer length")
    }
    it("should not share their buffers with key material", async function () {
        checkOwned(generateKey(), "key")
        const key = generateKey()
        const plaintext = randomBytes(cs + 100)
        const e = new Encrypter(key, "ctx")
        const d = new Decrypter(key, "ctx")

        const ciphertext = await e.encrypt(plaintext)
        checkOwned(ciphertext, "ciphertext")
        checkOwned(await d.decrypt(ciphertext), "plaintext")

        const encrypted = stream(plaintext).pipeThrough(new EncryptionStream(key, "ctx")).getReader()
        const chunks: Uint8Array<ArrayBuffer>[] = []
        for (; ;) {
            const { done, value } = await encrypted.read()
            if (done) break
            checkOwned(value, "ciphertext chunk " + chunks.length.toString())
            chunks.push(value)
        }
        assert.equal(chunks[0].length, 24, "salt")
        assert.equal(chunks[1].length, 32, "commitment")
        const decrypted = stream(flatten(chunks)).pipeThrough(new DecryptionStream(key, "ctx")).getReader()
        for (; ;) {
            const { done, value } = await decrypted.read()
            if (done) break
            checkOwned(value, "plaintext chunk")
        }

        const r = await d.decryptBlob(new Blob([ciphertext]))
        checkOwned(await r.bytes(), "bytes")
        checkOwned(await r.slice(100, 200).bytes(), "slice")
        checkOwned(await readAll(r.stream()), "stream")
        assert.equal((await r.arrayBuffer()).byteLength, r.size, "arrayBuffer")
    })
    it("should survive the header buffers being transferred", async function () {
        const key = generateKey()
        const plaintext = randomBytes(cs + 100)
        const s = new EncryptionStream(key, "ctx")
        const writer = s.writable.getWriter()
        const reader = s.readable.getReader()
        const written = writer.write(plaintext).then(() => writer.close())

        const header: Uint8Array[] = []
        for (let i = 0; i < 2; i++) {
            const { done, value } = await reader.read()
            if (done) throw Error("stream ended early")
            header.push(new Uint8Array(value))
            // Detaching the buffer must not affect the stream's internal state.
            structuredClone(value, { transfer: [value.buffer] })
            assert.equal(value.byteLength, 0)
        }
        // The write only completes once the rest is read.
        const rest = await readAll(new ReadableStream({
            async pull(controller) {
                const { done, value } = await reader.read()
                if (done) controller.close()
                else controller.enqueue(value)
            },
        }))
        await written
        const plaintextAgain = await new Decrypter(key, "ctx").decrypt(flatten([...header, rest]))
        assert.deepEqual(plaintextAgain, plaintext)
    })
    it("should consume each chunk before the write completes", async function () {
        const key = generateKey()
        const s = new EncryptionStream(key, "ctx")
        const writer = s.writable.getWriter()
        const reading = readAll(s.readable)
        // Reuse a single buffer for every write, like a reader loop would.
        const buffer = new Uint8Array(4 * cs)
        for (let i = 1; i <= 5; i++) {
            buffer.fill(i)
            await writer.write(buffer)
        }
        buffer.fill(0)
        await writer.close()
        const plaintext = await new Decrypter(key, "ctx").decrypt(await reading)
        assert.equal(plaintext.length, 5 * 4 * cs)
        for (let i = 1; i <= 5; i++) {
            const record = plaintext.subarray((i - 1) * 4 * cs, i * 4 * cs)
            assert.isTrue(record.every((b) => b === i), "record " + i.toString())
        }
    })
    it("should reject close on a truncated ciphertext", async function () {
        const key = generateKey()
        const ciphertext = await new Encrypter(key, "ctx").encrypt(randomBytes(cs + 100))
        const s = new DecryptionStream(key, "ctx")
        const writer = s.writable.getWriter()
        const reading = readAll(s.readable)
        await writer.write(ciphertext.subarray(0, headerSize + encChunkSize))
        await expect(writer.close()).rejects.toThrow(/unexpected EOF/)
        await expect(reading).rejects.toThrow(/unexpected EOF/)
    })
    it("should not expose the key as a property", function () {
        const key = generateKey()
        assert.equal(JSON.stringify(new Encrypter(key, "ctx")), "{}")
        assert.equal(JSON.stringify(new Decrypter(key, "ctx")), "{}")
        assert.deepEqual(Object.keys(new EncryptionStream(key, "ctx")), ["readable", "writable"])
        assert.deepEqual(Object.keys(new DecryptionStream(key, "ctx")), ["readable", "writable"])
    })
    it("should copy keys and contexts, even if slice returns a view", async function () {
        const wrappers: ((a: Uint8Array) => Uint8Array)[] = [viewSlicing]
        if (typeof Buffer !== "undefined") {
            wrappers.push((a) => Buffer.from(a))
        }
        for (const wrap of wrappers) {
            const key = wrap(generateKey())
            const context = wrap(bytes("ctx"))
            const original = { key: new Uint8Array(key), context: new Uint8Array(context) }
            const e = new Encrypter(key, context)
            const d = new Decrypter(key, context)
            const es = new EncryptionStream(key, context)
            const ds = new DecryptionStream(key, context)
            key.fill(0)
            context.fill(0)

            const check = new Decrypter(original.key, original.context)
            const ciphertext = await e.encrypt(bytes("cobblestone"))
            assert.equal(text(await check.decrypt(ciphertext)), "cobblestone")
            assert.equal(text(await d.decrypt(ciphertext)), "cobblestone")
            const streamed = await readAll(stream(bytes("cobblestone")).pipeThrough(es))
            assert.equal(text(await check.decrypt(streamed)), "cobblestone")
            assert.equal(text(await readAll(stream(streamed).pipeThrough(ds))), "cobblestone")
        }
    })
})

describe("random access", function () {
    it("should read arbitrary ranges", async function () {
        const key = generateKey()
        const plaintext = randomBytes(2 * cs + 500)
        const ciphertext = await new Encrypter(key, "ctx").encrypt(plaintext)
        const d = new Decrypter(key, "ctx")
        for (const src of [blob(ciphertext), customSliceable(ciphertext)]) {
            const r = await d.decryptBlob(src)
            assert.equal(r.size, plaintext.length)
            assert.equal(r.size, plaintextSize(ciphertext.length))
            assert.deepEqual(await r.bytes(), plaintext)
            assert.deepEqual(await r.slice(0, 10).bytes(), plaintext.subarray(0, 10))
            assert.deepEqual(await r.slice(cs - 5, cs + 5).bytes(), plaintext.subarray(cs - 5, cs + 5))
            assert.deepEqual(await r.slice(2 * cs + 400).bytes(), plaintext.subarray(2 * cs + 400))
            // Like Blob.slice, negative indexes count from the end, and out
            // of range indexes are clamped.
            assert.deepEqual(await r.slice(2 * cs + 400, 3 * cs).bytes(), plaintext.subarray(2 * cs + 400))
            assert.deepEqual(await r.slice(-100).bytes(), plaintext.subarray(plaintext.length - 100))
            assert.deepEqual(await r.slice(-100, -50).bytes(), plaintext.subarray(plaintext.length - 100, plaintext.length - 50))
            assert.deepEqual(await r.slice(r.size).bytes(), new Uint8Array(0))
            assert.deepEqual(await r.slice(r.size + 1, r.size + 10).bytes(), new Uint8Array(0))
            assert.deepEqual(await r.slice(10, 5).bytes(), new Uint8Array(0))
            // Views are lazy and can be sliced again.
            assert.equal(r.slice(cs - 5, cs + 5).size, 10)
            assert.deepEqual(await r.slice(cs - 5, cs + 5).slice(2, -2).bytes(), plaintext.subarray(cs - 3, cs + 3))
            assert.deepEqual(await r.slice(cs - 5, cs + 5).slice(-1).bytes(), plaintext.subarray(cs + 4, cs + 5))
            assert.deepEqual(new Uint8Array(await r.slice(0, 10).arrayBuffer()), plaintext.subarray(0, 10))
            // stream() has the same semantics.
            assert.deepEqual(await readAll(r.stream()), plaintext)
            assert.deepEqual(await readAll(r.slice(cs - 5, cs + 5).stream()), plaintext.subarray(cs - 5, cs + 5))
            assert.deepEqual(await readAll(r.slice(-100).stream()), plaintext.subarray(plaintext.length - 100))
            assert.deepEqual(await readAll(r.slice(10, 5).stream()), new Uint8Array(0))
            assert.deepEqual(await readAll(r.slice(r.size).stream()), new Uint8Array(0))
        }
    })
    it("should read an empty message", async function () {
        const key = generateKey()
        const ciphertext = await new Encrypter(key).encrypt(bytes(""))
        const r = await new Decrypter(key).decryptBlob(blob(ciphertext))
        assert.equal(r.size, 0)
        assert.deepEqual(await r.bytes(), new Uint8Array(0))
        assert.deepEqual(await r.slice(0, 10).bytes(), new Uint8Array(0))
    })
    it("should reject sources that don't resolve to an ArrayBuffer", async function () {
        const key = generateKey()
        const ciphertext = await new Encrypter(key).encrypt(randomBytes(100))
        const d = new Decrypter(key)
        for (const value of [56, "56", [1, 2, 3], new Uint8Array(56), null, undefined]) {
            const src: Sliceable = { size: ciphertext.length, slice: () => ({ arrayBuffer: () => Promise.resolve(value as unknown as ArrayBuffer) }) }
            await expect(d.decryptBlob(src), String(value)).rejects.toThrow(/must resolve to an ArrayBuffer/)
        }
    })
    it("should decrypt nested messages", async function () {
        const inner = generateKey()
        const outer = generateKey()
        const plaintext = randomBytes(cs + 500)
        const ciphertext = await new Encrypter(outer, "outer").encrypt(await new Encrypter(inner, "inner").encrypt(plaintext))
        // A DecryptedBlob is a Sliceable, so it can be decrypted in turn.
        const r = await new Decrypter(inner, "inner").decryptBlob(await new Decrypter(outer, "outer").decryptBlob(new Blob([ciphertext])))
        assert.equal(r.size, plaintext.length)
        assert.deepEqual(await r.bytes(), plaintext)
        assert.deepEqual(await r.slice(cs - 10, cs + 10).bytes(), plaintext.subarray(cs - 10, cs + 10))
    })
    it("should decrypt streamed ranges one chunk at a time", async function () {
        const key = generateKey()
        const plaintext = randomBytes(2 * cs + 500)
        const ciphertext = await new Encrypter(key).encrypt(plaintext)
        const r = await new Decrypter(key).decryptBlob(blob(ciphertext))
        const reader = r.slice(cs - 10, 2 * cs + 10).stream().getReader()
        const sizes: number[] = []
        for (; ;) {
            const { done, value } = await reader.read()
            if (done) break
            sizes.push(value.length)
        }
        assert.deepEqual(sizes, [10, cs, 10])
    })
    it("should error streams on corrupted chunks", async function () {
        const key = generateKey()
        const plaintext = randomBytes(2 * cs + 500)
        const ciphertext = await new Encrypter(key).encrypt(plaintext)
        ciphertext[headerSize + 10] ^= 0xff // first chunk
        const r = await new Decrypter(key).decryptBlob(blob(ciphertext)) // the final chunk is valid
        await expect(readAll(r.stream())).rejects.toThrow(/authentication failed/)
        assert.deepEqual(await readAll(r.slice(cs).stream()), plaintext.subarray(cs))
    })
    it("should authenticate the length by decrypting the final chunk", async function () {
        const key = generateKey()
        const ciphertext = await new Encrypter(key).encrypt(randomBytes(2 * cs + 500))
        const d = new Decrypter(key)
        const r = await d.decryptBlob(blob(ciphertext))
        assert.equal(r.size, 2 * cs + 500)
        // Remove the final chunk, leaving two valid full chunks.
        const truncated = ciphertext.subarray(0, headerSize + 2 * encChunkSize)
        await expect(d.decryptBlob(blob(truncated))).rejects.toThrow(/invalid encrypted message size/)
        // Corrupt the final chunk.
        const corrupted = ciphertext.slice()
        corrupted[corrupted.length - 1] ^= 0x01
        await expect(d.decryptBlob(blob(corrupted))).rejects.toThrow(/authentication failed/)
    })
    it("should work without Web Crypto", async function () {
        withoutWebCrypto()
        const key = generateKey()
        const plaintext = randomBytes(cs + 500)
        const ciphertext = await new Encrypter(key).encrypt(plaintext)
        const r = await new Decrypter(key).decryptBlob(blob(ciphertext))
        assert.deepEqual(await r.slice(cs - 100, cs + 100).bytes(), plaintext.subarray(cs - 100, cs + 100))
    })
})

describe("size functions", function () {
    it.for([0, 1, cs - 1, cs, cs + 1, 2 * cs, 2 * cs + 500])(
        "should round-trip plaintext size %s", function (ps) {
            assert.equal(plaintextSize(ciphertextSize(ps)), ps)
        })
    it("should compute the ciphertext size", function () {
        assert.equal(ciphertextSize(0), headerSize + overhead)
        assert.equal(ciphertextSize(1), headerSize + 1 + overhead)
        assert.equal(ciphertextSize(cs - 1), headerSize + cs - 1 + overhead)
        assert.equal(ciphertextSize(cs), headerSize + cs + 2 * overhead)
        assert.equal(ciphertextSize(cs + 1), headerSize + cs + 1 + 2 * overhead)
        assert.equal(ciphertextSize(2 * cs), headerSize + 2 * cs + 3 * overhead)
    })
    it.for([-1, 0, 1, 55, NaN, Number.MAX_SAFE_INTEGER + 1])(
        "should throw for ciphertext size %s", function (size) {
            assert.throws(() => plaintextSize(size), /input too short/)
        })
    it.for([56, 56 + 1, 56 + 15, 56 + encChunkSize, 56 + encChunkSize + 1, 56 + 2 * encChunkSize])(
        "should throw for invalid ciphertext size %s", function (size) {
            assert.throws(() => plaintextSize(size), /invalid encrypted message size/)
        })
    it("should handle the maximum message size", function () {
        const maxChunks = 2 ** 38
        const validSize = headerSize + (maxChunks - 1) * encChunkSize + overhead
        assert.equal(plaintextSize(validSize), (maxChunks - 1) * cs)
        assert.equal(ciphertextSize((maxChunks - 1) * cs), validSize)
        assert.equal(ciphertextSize(2 ** 52 - 1), validSize + cs - 1)
        assert.throws(() => plaintextSize(validSize + encChunkSize), /too large/)
        assert.throws(() => ciphertextSize(2 ** 52), /too large/)
    })
})

describe.skipIf(expect.getState().environment !== "node")("other realms", function () {
    it("should accept Uint8Arrays from other realms", async function () {
        const vm = await import("node:vm")
        const foreign = (n: number) => vm.runInNewContext("new Uint8Array(" + n.toString() + ")") as Uint8Array
        const key = foreign(16)
        assert.isFalse(key instanceof Uint8Array)
        const ciphertext = await new Encrypter(key, foreign(3)).encrypt(foreign(100))
        assert.equal((await new Decrypter(key, foreign(3)).decrypt(ciphertext)).length, 100)
        const d = new Decrypter(new Uint8Array(key), new Uint8Array(3))
        assert.equal((await d.decrypt(ciphertext)).length, 100)
        for (const notBytes of [vm.runInNewContext("new Uint16Array(8)"), vm.runInNewContext("new DataView(new ArrayBuffer(16))"), vm.runInNewContext("({ length: 16 })")]) {
            assert.throws(() => new Encrypter(notBytes as Uint8Array), /Uint8Array/)
        }
    })
})

describe.skipIf(expect.getState().environment !== "node")("esbuild", function () {
    it("should tree shake", async function () {
        const result = await (await import("esbuild")).build({
            stdin: {
                // Not using "cobblestone-encryption" to load the TS files directly.
                contents: 'import * as cobblestone from "./lib/index.js"',
                resolveDir: __dirname + "/..",
            },
            bundle: true,
            write: false,
        })
        assert.equal(result.outputFiles.length, 1)
        assert.equal(result.outputFiles[0].text, "(() => {\n})();\n")
    })
})

function withoutWebCrypto() {
    forceWebCryptoOff(true)
    onTestFinished(() => { forceWebCryptoOff(false) })
}

function blob(a: Uint8Array): Blob {
    return new Blob([a as Uint8Array<ArrayBuffer>])
}

// customSliceable is a Sliceable that is not a Blob, like one backed by HTTP
// Range requests would be.
function customSliceable(a: Uint8Array): Sliceable {
    return {
        size: a.length,
        slice: (start, end) => ({
            arrayBuffer: () => Promise.resolve(a.slice(start, end).buffer),
        }),
    }
}

function bytes(s: string): Uint8Array {
    return new TextEncoder().encode(s)
}

async function decryptStream(key: Uint8Array, context: string, ciphertext: Uint8Array): Promise<Uint8Array> {
    return await readAll(stream(ciphertext).pipeThrough(new DecryptionStream(key, context)))
}

async function sliceOrFail(r: Promise<DecryptedBlob>): Promise<Uint8Array> {
    return await (await r).bytes()
}

function text(b: Uint8Array): string {
    return new TextDecoder().decode(b)
}

function randomBytesStream(n: number, chunk: number): ReadableStream<Uint8Array> {
    return new ReadableStream({
        start(controller) {
            for (let i = 0; i < n; i += chunk) {
                controller.enqueue(randomBytes(Math.min(chunk, n - i)))
            }
            controller.close()
        }
    })
}

// viewSlicing returns a copy of a whose slice method returns a view rather
// than a copy, like Node.js Buffers.
function viewSlicing(a: Uint8Array): Uint8Array {
    const v = new Uint8Array(a)
    Object.defineProperty(v, "slice", {
        value: (start?: number, end?: number) => v.subarray(start, end),
    })
    return v
}

function rechunk(size: number): TransformStream<Uint8Array, Uint8Array> {
    return new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
            for (let i = 0; i < chunk.length; i += size) {
                controller.enqueue(chunk.subarray(i, i + size))
            }
        }
    })
}

class HashingTransformStream extends TransformStream<Uint8Array, Uint8Array> {
    digest: Uint8Array | null = null
    constructor() {
        const h = sha256.create()
        super({
            transform: (chunk, controller) => {
                h.update(chunk)
                controller.enqueue(chunk)
            },
            flush: () => {
                this.digest = h.digest()
            }
        })
    }
}

class SizeTransformStream extends TransformStream<Uint8Array, Uint8Array> {
    size = 0
    constructor() {
        super({
            transform: (chunk, controller) => {
                this.size += chunk.length
                controller.enqueue(chunk)
            }
        })
    }
}

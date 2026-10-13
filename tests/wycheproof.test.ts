// Wycheproof test vectors for c2sp.org/chunked-encryption, applied as
// described in https://github.com/C2SP/wycheproof/blob/main/doc/c2sp_chunked_encryption.md

import { describe, it, assert, expect, onTestFinished } from "vitest"
import { sha512 } from "@noble/hashes/sha2.js"
import { hex } from "@scure/base"
import { Decrypter, DecryptionStream, Encrypter, EncryptionStream, ciphertextSize, plaintextSize } from "../lib/index.js"
import { aesGCM, forceWebCryptoOff } from "../lib/aesgcm.js"
import * as chunked from "../lib/chunked.js"
import { flatten, readAll, stream } from "../lib/io.js"
import type { DecryptedBlob } from "../lib/io.js"
import vectors128 from "./wycheproof/c2sp_chunked_encryption_aes_128_gcm_test.json" with { type: "json" }
import vectors256 from "./wycheproof/c2sp_chunked_encryption_aes_256_gcm_test.json" with { type: "json" }

const itSlowly = typeof process !== "undefined" && process.env.SLOW ? it : it.skip

const headerSize = 56

interface Vector {
    tcId: number
    comment: string
    key: string
    ctx: string
    ct: string
    aeadKey?: string
    baseNonce?: string
    msgLength?: number
    msgSha512?: string
    result: "valid" | "invalid"
    flags: string[]
}

interface VectorFile {
    algorithm: string
    numberOfTests: number
    testGroups: {
        type: string
        aead: string
        sha: string
        tests: Vector[]
    }[]
}

describe("Wycheproof", function () {
    for (const file of [vectors128, vectors256] as unknown as VectorFile[]) {
        let count = 0
        for (const group of file.testGroups) {
            for (const vec of group.tests) {
                count++
                const name = file.algorithm + "/tc" + vec.tcId.toString() + ": " + vec.comment
                describe(name, async function () {
                    const key = hex.decode(vec.key)
                    const ctx = hex.decode(vec.ctx)
                    const ct = await inflate(hex.decode(vec.ct))
                    const flags = new Set(vec.flags)
                    const itSlowlyIfBig = ct.length > 1024 * 1024 ? it.skip : ct.length > 1024 ? itSlowly : it

                    // The instantiation is selected by the AEAD, and the
                    // hash is always SHA-512.
                    assert.equal(group.sha, "SHA-512")
                    // Only Cobblestone-128 is provided through the high-level
                    // API. The other instantiation is tested in raw mode.
                    const cobblestone128 = group.aead === "AEAD_AES_128_GCM"

                    // For valid vectors, the message length and hash. For
                    // invalid ones, the longest valid message prefix, which
                    // may be empty.
                    const prefixLength = vec.msgLength ?? 0
                    const checkMessage = (msg: Uint8Array) => {
                        assert.equal(msg.length, vec.msgLength)
                        assert.equal(hex.encode(sha512(msg)), vec.msgSha512)
                    }
                    const checkPrefix = (data: Uint8Array) => {
                        assert.isAtMost(data.length, prefixLength, "produced more than the valid prefix")
                        if (data.length === prefixLength && vec.msgSha512 !== undefined) {
                            assert.equal(hex.encode(sha512(data)), vec.msgSha512)
                        }
                    }

                    if (vec.result === "valid") {
                        it("should compute the plaintext size", function () {
                            assert.equal(plaintextSize(ct.length), vec.msgLength)
                            assert.equal(ciphertextSize(vec.msgLength ?? -1), ct.length)
                            assert.equal(chunked.plaintextSize(ct.length - headerSize), vec.msgLength)
                        })
                    }

                    if (!cobblestone128 && flags.has("HeaderFailure")) {
                        it.skip("should fail (Cobblestone-256 is only implemented in raw mode)")
                    } else if (flags.has("InvalidKeySize")) {
                        it("should reject the key", function () {
                            assert.notEqual(key.length, 16)
                            assert.throws(() => new Decrypter(key, ctx), /invalid key size/)
                            assert.throws(() => new Encrypter(key, ctx), /invalid key size/)
                        })
                    } else if (cobblestone128 && vec.result === "valid") {
                        it("should decrypt", async function () {
                            const d = new Decrypter(key, ctx)
                            checkMessage(await d.decrypt(ct))
                        })
                        it("should decrypt via streaming", async function () {
                            checkMessage(await readAll(stream(ct).pipeThrough(new DecryptionStream(key, ctx))))
                        })
                        it("should decrypt via streaming in pieces", async function () {
                            checkMessage(await readAll(streamInPieces(ct, 1000).pipeThrough(new DecryptionStream(key, ctx))))
                        })
                        itSlowlyIfBig("should decrypt via streaming byte-by-byte", async function () {
                            checkMessage(await readAll(streamInPieces(ct, 1).pipeThrough(new DecryptionStream(key, ctx))))
                        })
                        it("should decrypt via random access", async function () {
                            const d = new Decrypter(key, ctx)
                            const r = await d.decryptBlob(blob(ct))
                            assert.equal(r.size, vec.msgLength)
                            checkMessage(await r.bytes())
                            assert.deepEqual(await r.slice(r.size).bytes(), new Uint8Array(0))
                            // Read it again in pieces, exercising the cache.
                            const pieces: Uint8Array[] = []
                            for (let off = 0; off < r.size; off += 1000) {
                                pieces.push(await r.slice(off, off + 1000).bytes())
                            }
                            checkMessage(flatten(pieces))
                            // Seek relative to the end, like an application
                            // reading a trailer would.
                            const tail = await r.slice(-100).bytes()
                            const message = await d.decrypt(ct)
                            assert.deepEqual(tail, message.subarray(Math.max(0, r.size - 100)))
                            // Read it as a stream, whole and in ranges.
                            checkMessage(await readAll(r.stream()))
                            assert.deepEqual(await readAll(r.slice(-100).stream()), tail)
                            assert.deepEqual(await readAll(r.slice(1000, 3000).stream()), message.subarray(1000, 3000))
                        })
                        it("should decrypt without Web Crypto", async function () {
                            withoutWebCrypto()
                            const d = new Decrypter(key, ctx)
                            checkMessage(await d.decrypt(ct))
                            const r = await d.decryptBlob(blob(ct))
                            checkMessage(await r.bytes())
                        })
                        it("should round-trip", async function () {
                            const d = new Decrypter(key, ctx)
                            const message = await d.decrypt(ct)
                            const e = new Encrypter(key, ctx)
                            const ciphertext = await e.encrypt(message)
                            assert.equal(ciphertext.length, ct.length)
                            checkMessage(await d.decrypt(ciphertext))
                            const r = await d.decryptBlob(blob(ciphertext))
                            checkMessage(await r.bytes())
                        })
                        it("should round-trip via streaming", async function () {
                            const d = new Decrypter(key, ctx)
                            const message = await d.decrypt(ct)
                            const ciphertext = streamInPieces(message, 1000).pipeThrough(new EncryptionStream(key, ctx))
                            checkMessage(await readAll(ciphertext.pipeThrough(new DecryptionStream(key, ctx))))
                        })
                    } else if (cobblestone128) {
                        it("should fail to decrypt", async function () {
                            const d = new Decrypter(key, ctx)
                            await expect(d.decrypt(ct)).rejects.toThrow()
                        })
                        if (flags.has("HeaderFailure")) {
                            it("should fail before decrypting any chunk", async function () {
                                const d = new Decrypter(key, ctx)
                                await expect(d.decrypt(ct)).rejects.toThrow(/invalid commitment|unexpected EOF/)
                                await expect(d.decryptBlob(blob(ct))).rejects.toThrow(/invalid commitment|input too short/)
                                // The stream errors without producing any output.
                                const { data, error } = await readUntilError(stream(ct).pipeThrough(new DecryptionStream(key, ctx)))
                                assert.instanceOf(error, Error)
                                assert.match(error.message, /invalid commitment|unexpected EOF/)
                                assert.equal(data.length, 0)
                            })
                        } else {
                            it("should fail via streaming", async function () {
                                const { data, error } = await readUntilError(stream(ct).pipeThrough(new DecryptionStream(key, ctx)))
                                assert.instanceOf(error, Error)
                                checkPrefix(data)
                            })
                            it("should fail via streaming in pieces", async function () {
                                const { data, error } = await readUntilError(streamInPieces(ct, 1000).pipeThrough(new DecryptionStream(key, ctx)))
                                assert.instanceOf(error, Error)
                                checkPrefix(data)
                            })
                            itSlowlyIfBig("should fail via streaming byte-by-byte", async function () {
                                const { data, error } = await readUntilError(streamInPieces(ct, 1).pipeThrough(new DecryptionStream(key, ctx)))
                                assert.instanceOf(error, Error)
                                // With a byte-by-byte source, every valid
                                // chunk is delivered before the error.
                                assert.equal(data.length, prefixLength)
                                checkPrefix(data)
                            })
                            it("should fail via random access", async function () {
                                const d = new Decrypter(key, ctx)
                                await checkRandomAccessFailure(d.decryptBlob(blob(ct)))
                            })
                        }
                        it("should fail without Web Crypto", async function () {
                            withoutWebCrypto()
                            const d = new Decrypter(key, ctx)
                            await expect(d.decrypt(ct)).rejects.toThrow()
                            await checkRandomAccessFailure(d.decryptBlob(blob(ct)))
                        })
                    }

                    // Raw mode applies to vectors that provide the derived AEAD
                    // key and base nonce, for both instantiations.
                    if (vec.aeadKey !== undefined && vec.baseNonce !== undefined) {
                        assert.isFalse(flags.has("HeaderFailure"))
                        const aeadKey = hex.decode(vec.aeadKey)
                        const baseNonce = hex.decode(vec.baseNonce)
                        const body = ct.subarray(headerSize)
                        assert.equal(aeadKey.length, group.aead === "AEAD_AES_128_GCM" ? 16 : 32)

                        if (vec.result === "valid") {
                            it("should decrypt in raw mode", async function () {
                                const aead = await aesGCM(aeadKey)
                                checkMessage(await readAll(stream(body).pipeThrough(new TransformStream(chunked.decryptChunks(aead, baseNonce)))))
                                checkMessage(await readAll(streamInPieces(body, 1000).pipeThrough(new TransformStream(chunked.decryptChunks(aead, baseNonce)))))
                            })
                            it("should decrypt in raw mode via random access", async function () {
                                const aead = await aesGCM(aeadKey)
                                const r = await chunked.decryptChunksRandomAccess(aead, baseNonce, blob(body))
                                assert.equal(r.size, vec.msgLength)
                                checkMessage(await r.bytes())
                                checkMessage(await readAll(r.stream()))
                            })
                            it("should re-encrypt deterministically in raw mode", async function () {
                                const aead = await aesGCM(aeadKey)
                                const message = await readAll(stream(body).pipeThrough(new TransformStream(chunked.decryptChunks(aead, baseNonce))))
                                const ciphertext = await readAll(stream(message).pipeThrough(new TransformStream(chunked.encryptChunks(aead, baseNonce))))
                                assert.deepEqual(ciphertext, body)
                                const inPieces = await readAll(streamInPieces(message, 1000).pipeThrough(new TransformStream(chunked.encryptChunks(aead, baseNonce))))
                                assert.deepEqual(inPieces, body)
                            })
                            it("should decrypt in raw mode without Web Crypto", async function () {
                                withoutWebCrypto()
                                const aead = await aesGCM(aeadKey)
                                checkMessage(await readAll(stream(body).pipeThrough(new TransformStream(chunked.decryptChunks(aead, baseNonce)))))
                                const r = await chunked.decryptChunksRandomAccess(aead, baseNonce, blob(body))
                                checkMessage(await r.bytes())
                            })
                        } else {
                            it("should fail in raw mode", async function () {
                                const aead = await aesGCM(aeadKey)
                                const { data, error } = await readUntilError(stream(body).pipeThrough(new TransformStream(chunked.decryptChunks(aead, baseNonce))))
                                assert.instanceOf(error, Error)
                                checkPrefix(data)
                            })
                            it("should fail in raw mode via random access", async function () {
                                const aead = await aesGCM(aeadKey)
                                await checkRandomAccessFailure(chunked.decryptChunksRandomAccess(aead, baseNonce, blob(body)))
                            })
                            it("should fail in raw mode without Web Crypto", async function () {
                                withoutWebCrypto()
                                const aead = await aesGCM(aeadKey)
                                await expect(readAll(stream(body).pipeThrough(new TransformStream(chunked.decryptChunks(aead, baseNonce))))).rejects.toThrow()
                                await checkRandomAccessFailure(chunked.decryptChunksRandomAccess(aead, baseNonce, blob(body)))
                            })
                        }
                    }

                    async function checkRandomAccessFailure(opened: Promise<DecryptedBlob>) {
                        // Authenticating the message length must fail, unless
                        // the final chunk is valid.
                        if (!flags.has("ValidFinalChunk")) {
                            await expect(opened).rejects.toThrow()
                            return
                        }
                        const r = await opened
                        await expect(r.bytes()).rejects.toThrow()
                        await expect(readAll(r.stream())).rejects.toThrow()
                        // Reading only validly encrypted chunks succeeds.
                        checkPrefix(await r.slice(0, prefixLength).bytes())
                    }
                })
            }
        }
        it(file.algorithm + " should have " + file.numberOfTests.toString() + " vectors", function () {
            assert.equal(count, file.numberOfTests)
        })
    }
})

function withoutWebCrypto() {
    forceWebCryptoOff(true)
    onTestFinished(() => { forceWebCryptoOff(false) })
}

function blob(a: Uint8Array): Blob {
    return new Blob([a as Uint8Array<ArrayBuffer>])
}

async function inflate(data: Uint8Array): Promise<Uint8Array> {
    // The Compression Streams API calls the zlib format "deflate".
    return await readAll(blob(data).stream().pipeThrough(new DecompressionStream("deflate")))
}

function streamInPieces(a: Uint8Array, size: number): ReadableStream<Uint8Array> {
    return new ReadableStream<Uint8Array>({
        start(controller) {
            for (let i = 0; i < a.length; i += size) {
                controller.enqueue(a.subarray(i, i + size))
            }
            controller.close()
        }
    })
}

async function readUntilError(s: ReadableStream<Uint8Array>): Promise<{ data: Uint8Array, error: unknown }> {
    const reader = s.getReader()
    const chunks: Uint8Array[] = []
    for (; ;) {
        try {
            const { done, value } = await reader.read()
            if (done) {
                return { data: flatten(chunks), error: null }
            }
            chunks.push(value)
        } catch (error) {
            // The stream must keep failing, rather than report a clean end.
            await expect(reader.read()).rejects.toThrow()
            return { data: flatten(chunks), error }
        }
    }
}

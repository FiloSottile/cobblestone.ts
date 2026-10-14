// Raw mode of c2sp.org/chunked-encryption, where key derivation is left to
// the caller. There is no salt, no commitment, and no key commitment.

import { nonceSize, tagSize, type AEAD } from "./aesgcm.js"
import { checkBytes, copyBytes, readRange, type DecryptedBlob, type Sliceable } from "./io.js"

export const chunkSize = /* @__PURE__ */ (() => 16 * 1024)()
export const chunkOverhead = /* @__PURE__ */ (() => tagSize)()
export const encChunkSize = /* @__PURE__ */ (() => chunkSize + chunkOverhead)()
const nonceCounterSize = 5 // ceil(38 / 8)
const maxChunks = /* @__PURE__ */ (() => 2 ** 38)()

export function encryptedChunkCount(encryptedSize: number): number {
    if (!Number.isSafeInteger(encryptedSize) || encryptedSize < 0) {
        throw Error("invalid encrypted message size: " + encryptedSize.toString())
    }
    // Integer arithmetic only, since floating point division of large
    // sizes (up to 2⁵³) by encChunkSize may be inexact.
    const rem = encryptedSize % encChunkSize
    const chunks = (encryptedSize - rem) / encChunkSize + (rem > 0 ? 1 : 0)

    // The final chunk must be shorter than a full chunk (but must include a
    // tag), so each plaintext size has exactly one valid encrypted size.
    const plaintextSize = encryptedSize - chunks * chunkOverhead
    const expChunks = Math.floor((plaintextSize + chunkSize) / chunkSize)
    if (expChunks !== chunks) {
        throw Error("invalid encrypted message size: " + encryptedSize.toString())
    }

    if (chunks > maxChunks) {
        throw Error("encrypted message too large: " + chunks.toString() +
            " chunks, want at most " + maxChunks.toString())
    }
    return chunks
}

export function plaintextSize(encryptedSize: number): number {
    const chunks = encryptedChunkCount(encryptedSize)
    return encryptedSize - chunks * chunkOverhead
}

export function ciphertextSize(plaintextSize: number): number {
    if (!Number.isSafeInteger(plaintextSize) || plaintextSize < 0) {
        throw Error("invalid plaintext size: " + plaintextSize.toString())
    }
    const chunks = Math.floor(plaintextSize / chunkSize) + 1
    if (chunks > maxChunks) {
        throw Error("message too large: " + chunks.toString() +
            " chunks, want at most " + maxChunks.toString())
    }
    return plaintextSize + chunks * chunkOverhead
}

export function chunkNonce(baseNonce: Uint8Array, chunkIndex: number): Uint8Array<ArrayBuffer> {
    if (chunkIndex >= maxChunks) {
        throw Error("chunk counter overflow")
    }
    const nonce = copyBytes(baseNonce)
    // XOR the chunk index as a big-endian 38-bit integer into the final
    // bytes of the base nonce.
    let c = chunkIndex
    for (let i = 1; i <= nonceCounterSize; i++) {
        nonce[nonce.length - i] ^= c % 256
        c = Math.floor(c / 256)
    }
    return nonce
}

function checkBaseNonce(baseNonce: Uint8Array): void {
    if (baseNonce.length !== nonceSize) {
        throw Error("invalid base nonce size: " + baseNonce.length.toString())
    }
}

// A ChunkTransformer is the transformer of a TransformStream<Uint8Array,
// Uint8Array>, so it can be wrapped as new TransformStream(transformer), or
// composed into a larger transformer.
export interface ChunkTransformer {
    transform(chunk: Uint8Array, controller: TransformStreamDefaultController<Uint8Array<ArrayBuffer>>): Promise<void>
    flush(controller: TransformStreamDefaultController<Uint8Array<ArrayBuffer>>): Promise<void>
}

export function encryptChunks(aead: AEAD, baseNonce: Uint8Array): ChunkTransformer {
    checkBaseNonce(baseNonce)
    let counter = 0

    const plaintextBuffer = new Uint8Array(chunkSize)
    let plaintextBufferUsed = 0

    return {
        async transform(chunk, controller) {
            checkBytes(chunk, "chunk")
            while (chunk.length > 0) {
                const n = Math.min(plaintextBuffer.length - plaintextBufferUsed, chunk.length)
                plaintextBuffer.set(chunk.subarray(0, n), plaintextBufferUsed)
                plaintextBufferUsed += n
                chunk = chunk.subarray(n)

                // The final chunk is always shorter than a full chunk, so a
                // full buffer can be encrypted right away.
                if (plaintextBufferUsed === plaintextBuffer.length) {
                    const nonce = chunkNonce(baseNonce, counter)
                    counter++
                    controller.enqueue(await aead.seal(nonce, plaintextBuffer))
                    plaintextBufferUsed = 0
                }
            }
        },
        async flush(controller) {
            const nonce = chunkNonce(baseNonce, counter)
            counter++
            controller.enqueue(await aead.seal(nonce, plaintextBuffer.subarray(0, plaintextBufferUsed)))
        },
    }
}

export function decryptChunks(aead: AEAD, baseNonce: Uint8Array): ChunkTransformer {
    checkBaseNonce(baseNonce)
    let counter = 0

    const ciphertextBuffer = new Uint8Array(encChunkSize)
    let ciphertextBufferUsed = 0

    return {
        async transform(chunk, controller) {
            checkBytes(chunk, "chunk")
            while (chunk.length > 0) {
                const n = Math.min(ciphertextBuffer.length - ciphertextBufferUsed, chunk.length)
                ciphertextBuffer.set(chunk.subarray(0, n), ciphertextBufferUsed)
                ciphertextBufferUsed += n
                chunk = chunk.subarray(n)

                // A full encrypted chunk is never the final one, which must
                // be shorter, so it can be decrypted and released right away.
                if (ciphertextBufferUsed === ciphertextBuffer.length) {
                    const nonce = chunkNonce(baseNonce, counter)
                    counter++
                    controller.enqueue(await aead.open(nonce, ciphertextBuffer))
                    ciphertextBufferUsed = 0
                }
            }
        },
        async flush(controller) {
            if (ciphertextBufferUsed < chunkOverhead) {
                // The final chunk is missing (the ciphertext is empty or ended
                // on a chunk boundary) or is too short to be valid.
                throw Error("unexpected EOF: ciphertext is truncated")
            }
            const nonce = chunkNonce(baseNonce, counter)
            counter++
            controller.enqueue(await aead.open(nonce, ciphertextBuffer.subarray(0, ciphertextBufferUsed)))
        },
    }
}

export async function decryptChunksRandomAccess(aead: AEAD, baseNonce: Uint8Array, src: Sliceable): Promise<DecryptedBlob> {
    checkBaseNonce(baseNonce)
    const chunks = encryptedChunkCount(src.size)
    const size = src.size - chunks * chunkOverhead

    const readChunk = async (chunkIndex: number): Promise<Uint8Array> => {
        const chunkOff = chunkIndex * encChunkSize
        const chunkLen = Math.min(encChunkSize, src.size - chunkOff)
        const ciphertext = await readRange(src, chunkOff, chunkOff + chunkLen)
        return await aead.open(chunkNonce(baseNonce, chunkIndex), ciphertext)
    }

    // Decrypting the final chunk authenticates the message length. It's also
    // the most likely chunk to be requested first, by applications seeking
    // relative to the end of the message, so it starts out as the cached one.
    const finalChunkIndex = chunks - 1
    let cache = { index: finalChunkIndex, data: await readChunk(finalChunkIndex) }

    // read returns the plaintext between s (inclusive) and e (exclusive),
    // which must be within the message.
    const read = async (s: number, e: number): Promise<Uint8Array<ArrayBuffer>> => {
        const out = new Uint8Array(e - s)
        let n = 0
        while (s + n < e) {
            const chunkIndex = Math.floor((s + n) / chunkSize)
            if (cache.index !== chunkIndex) {
                cache = { index: chunkIndex, data: await readChunk(chunkIndex) }
            }
            const plaintext = cache.data
            const plainChunkOff = (s + n) - chunkIndex * chunkSize
            const copySize = Math.min(plaintext.length - plainChunkOff, e - s - n)
            out.set(plaintext.subarray(plainChunkOff, plainChunkOff + copySize), n)
            n += copySize
        }
        return out
    }

    // view returns a Blob-like view of the plaintext between s and e.
    const view = (s: number, e: number): DecryptedBlob => ({
        size: e - s,
        slice(start?: number, end?: number): DecryptedBlob {
            const [ss, ee] = sliceRange(e - s, start, end)
            return view(s + ss, s + ee)
        },
        async arrayBuffer(): Promise<ArrayBuffer> {
            return (await read(s, e)).buffer
        },
        bytes(): Promise<Uint8Array<ArrayBuffer>> {
            return read(s, e)
        },
        stream(): ReadableStream<Uint8Array<ArrayBuffer>> {
            let offset = s
            return new ReadableStream<Uint8Array<ArrayBuffer>>({
                async pull(controller) {
                    if (offset >= e) {
                        controller.close()
                        return
                    }
                    // One chunk per pull, so that only what's read is
                    // decrypted.
                    const chunkEnd = Math.min((Math.floor(offset / chunkSize) + 1) * chunkSize, e)
                    controller.enqueue(await read(offset, chunkEnd))
                    offset = chunkEnd
                },
            })
        },
    })
    return view(0, size)
}

// sliceRange normalizes slice indexes like Blob.slice: missing indexes
// default to the whole range, negative indexes count from the end, and out of
// range indexes are clamped.
function sliceRange(size: number, start = 0, end = size): [number, number] {
    const normalize = (i: number): number => {
        i = clampedLongLong(i)
        return i < 0 ? Math.max(size + i, 0) : Math.min(i, size)
    }
    const s = normalize(start)
    return [s, Math.max(normalize(end), s)]
}

// clampedLongLong converts a value like the Web IDL [Clamp] long long type
// used by Blob.slice: NaN becomes 0, infinities and values out of range are
// clamped, and fractions are rounded to the nearest integer, choosing the even
// one in case of a tie. Note that not all runtimes implement this correctly.
// https://webidl.spec.whatwg.org/#abstract-opdef-converttoint
function clampedLongLong(value: unknown): number {
    if (typeof value === "bigint") {
        throw TypeError("can't convert a BigInt to a number")
    }
    let x = Number(value)
    if (Number.isNaN(x)) return 0
    x = Math.min(Math.max(x, -(2 ** 53 - 1)), 2 ** 53 - 1)
    const floor = Math.floor(x)
    if (x - floor === 0.5) {
        return floor % 2 === 0 ? floor : floor + 1
    }
    return Math.round(x)
}

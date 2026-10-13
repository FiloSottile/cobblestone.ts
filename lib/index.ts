import { hmac } from "@noble/hashes/hmac.js"
import { sha512 } from "@noble/hashes/sha2.js"
import { aesGCM, nonceSize, type AEAD } from "./aesgcm.js"
import { decryptChunks, decryptChunksRandomAccess, encryptChunks, ciphertextSize as rawCiphertextSize, plaintextSize as rawPlaintextSize } from "./chunked.js"
import type { ChunkTransformer } from "./chunked.js"
import { checkBytes, copyBytes, flatten, randomBytes, readAll, readRange, section, stream } from "./io.js"
import type { DecryptedBlob, Sliceable } from "./io.js"

export type { DecryptedBlob, Sliceable }

/**
 * The size of a Cobblestone-128 key, in bytes.
 */
export const keySize = 16

const saltSize = 24
const commitmentSize = 32
const headerSize = /* @__PURE__ */ (() => saltSize + commitmentSize)()

/**
 * Generate a new random key for Cobblestone-128.
 *
 * A single key can be used to encrypt a practically unlimited number of
 * messages. It must be kept secret, and must be uniformly random (never a
 * password): use this function, or the output of a KDF.
 *
 * @returns A new 16-byte key.
 */
export function generateKey(): Uint8Array<ArrayBuffer> {
    return randomBytes(keySize)
}

/**
 * Calculate the size of the plaintext corresponding to a given ciphertext
 * size.
 *
 * @param ciphertextSize - The size of the ciphertext, in bytes.
 *
 * @returns The size of the plaintext, in bytes.
 *
 * @throws If the ciphertext size is too small or invalid. Only one
 * ciphertext size is valid for each plaintext size.
 */
export function plaintextSize(ciphertextSize: number): number {
    if (!Number.isSafeInteger(ciphertextSize) || ciphertextSize < headerSize) {
        throw Error("input too short")
    }
    return rawPlaintextSize(ciphertextSize - headerSize)
}

/**
 * Calculate the size of the ciphertext corresponding to a given plaintext
 * size.
 *
 * @param plaintextSize - The size of the plaintext, in bytes.
 *
 * @returns The size of the ciphertext, in bytes.
 *
 * @throws If the plaintext size is negative or larger than the maximum
 * message size (4 PiB - 1 byte).
 */
export function ciphertextSize(plaintextSize: number): number {
    return headerSize + rawCiphertextSize(plaintextSize)
}

const infoPrefix = "c2sp.org/chunked-encryption@v1+AEAD_AES_128_GCM\x00"

// HKDF-Expand from RFC 5869, Section 2.3. Unlike @noble/hashes/hkdf, it
// accepts a PRK shorter than the hash output, since the input key is used
// directly as the PRK.
function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    const out = new Uint8Array(length)
    let t = new Uint8Array(0)
    for (let i = 1, n = 0; n < length; i++) {
        t = hmac(sha512, prk, flatten([t, info, new Uint8Array([i])]))
        out.set(t.subarray(0, Math.min(t.length, length - n)), n)
        n += t.length
    }
    return out
}

async function expandKey(key: Uint8Array, salt: Uint8Array, context: Uint8Array): Promise<{
    aead: AEAD, baseNonce: Uint8Array, commitment: Uint8Array<ArrayBuffer>,
}> {
    // key || base nonce || commitment = HKDF-Expand(prk = input key,
    //     info = "c2sp.org/chunked-encryption@v1+" || aead || 0x00 || salt || context)
    const info = flatten([new TextEncoder().encode(infoPrefix), salt, context])
    const out = hkdfExpand(key, info, keySize + nonceSize + commitmentSize)
    // The outputs are copied into separate allocations, since the commitment
    // leaves the library as part of the ciphertext, and must not share its
    // underlying buffer with the key and base nonce.
    const aead = await aesGCM(copyBytes(out.subarray(0, keySize)))
    const baseNonce = copyBytes(out.subarray(keySize, keySize + nonceSize))
    const commitment = copyBytes(out.subarray(keySize + nonceSize))
    return { aead, baseNonce, commitment }
}

async function checkHeader(key: Uint8Array, context: Uint8Array, header: Uint8Array): Promise<{
    aead: AEAD, baseNonce: Uint8Array,
}> {
    const salt = header.subarray(0, saltSize)
    const commitment = header.subarray(saltSize, headerSize)
    const { aead, baseNonce, commitment: expected } = await expandKey(key, salt, context)
    if (!compareBytes(commitment, expected)) {
        throw Error("invalid commitment")
    }
    return { aead, baseNonce }
}

function checkKey(key: Uint8Array): Uint8Array {
    checkBytes(key, "key")
    if (key.length !== keySize) {
        throw Error("invalid key size: " + key.length.toString())
    }
    return copyBytes(key)
}

function encodeContext(context: Uint8Array | string | undefined): Uint8Array {
    if (context === undefined) {
        return new Uint8Array(0)
    }
    if (typeof context === "string") {
        return new TextEncoder().encode(context)
    }
    checkBytes(context, "context")
    return copyBytes(context)
}

/**
 * Encrypts messages with Cobblestone-128 using the given key and context.
 *
 * Each call to {@link Encrypter.encrypt} encrypts a single message with a
 * fresh random salt, so the same Encrypter can be used for multiple messages.
 * To encrypt a ReadableStream, use {@link EncryptionStream} instead.
 */
export class Encrypter {
    #key: Uint8Array
    #context: Uint8Array

    /**
     * @param key - The 16-byte key to encrypt the message(s) with. It must
     * be uniformly random, for example generated by {@link generateKey}.
     * @param context - Optional data bound to the ciphertext, which can be
     * used to bind a message to e.g. a filename or a user ID, or for domain
     * separation (e.g. `"myapp v2 backup encryption"`). It is not secret and
     * it is not part of the ciphertext, so the decrypting party must know it
     * independently. If a string is passed, it will be encoded as UTF-8.
     *
     * @throws If the key is not 16 bytes long.
     */
    constructor(key: Uint8Array, context?: Uint8Array | string) {
        this.#key = checkKey(key)
        this.#context = encodeContext(context)
    }

    /**
     * Encrypt a message using the configured key and context.
     *
     * @param plaintext - The message to encrypt.
     *
     * @returns A promise that resolves to the ciphertext. Its size is
     * {@link ciphertextSize} of the size of the message.
     */
    async encrypt(plaintext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
        checkBytes(plaintext, "plaintext")
        return await readAll(stream(plaintext).pipeThrough(new EncryptionStream(this.#key, this.#context)))
    }
}

/**
 * Decrypts messages encrypted with Cobblestone-128 using the given key and
 * context.
 *
 * To decrypt a ReadableStream, use {@link DecryptionStream} instead.
 */
export class Decrypter {
    #key: Uint8Array
    #context: Uint8Array

    /**
     * @param key - The 16-byte key the message(s) were encrypted with.
     * @param context - The context the message(s) were encrypted with, if
     * any. If a string is passed, it will be encoded as UTF-8.
     *
     * @throws If the key is not 16 bytes long.
     */
    constructor(key: Uint8Array, context?: Uint8Array | string) {
        this.#key = checkKey(key)
        this.#context = encodeContext(context)
    }

    /**
     * Decrypt a message using the configured key and context.
     *
     * @param ciphertext - The message to decrypt.
     *
     * @returns A promise that resolves to the decrypted message.
     *
     * @throws If the message was encrypted with a different key or context,
     * or has been modified, truncated, or extended.
     */
    async decrypt(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
        checkBytes(ciphertext, "ciphertext")
        return await readAll(stream(ciphertext).pipeThrough(new DecryptionStream(this.#key, this.#context)))
    }

    /**
     * Open a message for random access decryption using the configured key
     * and context.
     *
     * The message size is authenticated before the promise resolves, by
     * decrypting the final chunk. The other chunks are decrypted and
     * authenticated as they are read, so reading only part of the message
     * does not require processing the whole ciphertext.
     *
     * @param ciphertext - The message to decrypt, as a
     * {@link https://developer.mozilla.org/en-US/docs/Web/API/Blob | Blob}
     * (e.g. a File), or as any other {@link Sliceable} (e.g. backed by HTTP
     * Range requests).
     *
     * @returns A promise that resolves to a {@link DecryptedBlob}, which can
     * be read like a Blob.
     *
     * @throws If the message was encrypted with a different key or context,
     * or if its header or final chunk has been modified, or if its size is
     * invalid.
     */
    async decryptBlob(ciphertext: Sliceable): Promise<DecryptedBlob> {
        if (!Number.isSafeInteger(ciphertext.size) || ciphertext.size < headerSize) {
            throw Error("input too short")
        }
        const header = await readRange(ciphertext, 0, headerSize)
        const { aead, baseNonce } = await checkHeader(this.#key, this.#context, header)
        return await decryptChunksRandomAccess(aead, baseNonce, section(ciphertext, headerSize))
    }
}

/**
 * A transform stream that encrypts a message with Cobblestone-128 using the
 * given key and context, to be used with
 * {@link https://developer.mozilla.org/en-US/docs/Web/API/ReadableStream/pipeThrough | ReadableStream.pipeThrough}
 * like a
 * {@link https://developer.mozilla.org/en-US/docs/Web/API/CompressionStream | CompressionStream}.
 *
 * Each instance encrypts a single message with a fresh random salt, and like
 * any transform stream can't be reused. The output starts with the 56-byte
 * header (salt and commitment), and its size is {@link ciphertextSize} of
 * the size of the input.
 */
export class EncryptionStream implements ReadableWritablePair<Uint8Array<ArrayBuffer>, Uint8Array> {
    /**
     * The ciphertext.
     */
    readonly readable: ReadableStream<Uint8Array<ArrayBuffer>>
    /**
     * The plaintext.
     */
    readonly writable: WritableStream<Uint8Array>

    /**
     * @param key - The 16-byte key to encrypt the message with. It must be
     * uniformly random, for example generated by {@link generateKey}.
     * @param context - Optional data bound to the ciphertext. See
     * {@link Encrypter}. If a string is passed, it will be encoded as UTF-8.
     *
     * @throws If the key is not 16 bytes long.
     */
    constructor(key: Uint8Array, context?: Uint8Array | string) {
        const k = checkKey(key)
        const ctx = encodeContext(context)
        let chunks: ChunkTransformer | null = null
        const transform = new TransformStream<Uint8Array, Uint8Array<ArrayBuffer>>({
            async start(controller) {
                const salt = randomBytes(saltSize)
                const { aead, baseNonce, commitment } = await expandKey(k, salt, ctx)
                controller.enqueue(salt)
                controller.enqueue(commitment)
                chunks = encryptChunks(aead, baseNonce)
            },
            async transform(chunk, controller) {
                if (chunks === null) throw Error("internal error: transform called before start")
                await chunks.transform(chunk, controller)
            },
            async flush(controller) {
                if (chunks === null) throw Error("internal error: flush called before start")
                await chunks.flush(controller)
            },
        })
        this.readable = transform.readable
        this.writable = transform.writable
    }
}

/**
 * A transform stream that decrypts a message encrypted with Cobblestone-128
 * using the given key and context, to be used with
 * {@link https://developer.mozilla.org/en-US/docs/Web/API/ReadableStream/pipeThrough | ReadableStream.pipeThrough}
 * like a
 * {@link https://developer.mozilla.org/en-US/docs/Web/API/DecompressionStream | DecompressionStream}.
 *
 * The 56-byte header is processed, and the commitment checked, as soon as it
 * is received. The stream errors if the message was encrypted with a
 * different key or context, or has been modified, truncated, or extended.
 * Each chunk of the plaintext is authenticated before it's produced, but the
 * message could still turn out to be truncated: an application acting on
 * the plaintext before the stream ends must be prepared to discard its work
 * if the stream errors.
 */
export class DecryptionStream implements ReadableWritablePair<Uint8Array<ArrayBuffer>, Uint8Array> {
    /**
     * The plaintext.
     */
    readonly readable: ReadableStream<Uint8Array<ArrayBuffer>>
    /**
     * The ciphertext.
     */
    readonly writable: WritableStream<Uint8Array>

    /**
     * @param key - The 16-byte key the message was encrypted with.
     * @param context - The context the message was encrypted with, if any.
     * If a string is passed, it will be encoded as UTF-8.
     *
     * @throws If the key is not 16 bytes long.
     */
    constructor(key: Uint8Array, context?: Uint8Array | string) {
        const k = checkKey(key)
        const ctx = encodeContext(context)
        const header = new Uint8Array(headerSize)
        let headerUsed = 0
        let chunks: ChunkTransformer | null = null
        const transform = new TransformStream<Uint8Array, Uint8Array<ArrayBuffer>>({
            async transform(chunk, controller) {
                if (chunks === null) {
                    checkBytes(chunk, "chunk")
                    const n = Math.min(headerSize - headerUsed, chunk.length)
                    header.set(chunk.subarray(0, n), headerUsed)
                    headerUsed += n
                    chunk = chunk.subarray(n)
                    if (headerUsed < headerSize) return
                    const { aead, baseNonce } = await checkHeader(k, ctx, header)
                    chunks = decryptChunks(aead, baseNonce)
                }
                await chunks.transform(chunk, controller)
            },
            async flush(controller) {
                if (chunks === null) {
                    throw Error("unexpected EOF: ciphertext is truncated")
                }
                await chunks.flush(controller)
            },
        })
        this.readable = transform.readable
        this.writable = transform.writable
    }
}

function compareBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) { return false }
    let acc = 0
    for (let i = 0; i < a.length; i++) {
        acc |= a[i] ^ b[i]
    }
    return acc === 0
}

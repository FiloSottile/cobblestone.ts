import { gcm } from "@noble/ciphers/aes.js"

/**
 * An AEAD with 96-bit nonces and 16-byte authentication tags. The outputs are
 * always freshly allocated.
 */
export interface AEAD {
    seal(nonce: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array<ArrayBuffer>>
    open(nonce: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>>
}

export const nonceSize = 12
export const tagSize = 16

let webCryptoOff = false

export function forceWebCryptoOff(off: boolean): void {
    webCryptoOff = off
}

function subtleCrypto(): SubtleCrypto | null {
    if (webCryptoOff) {
        return null
    }
    // Browsers only expose crypto.subtle in secure contexts. The casts make
    // TypeScript consider the possibility that it's missing.
    const c = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto
    return c?.subtle ?? null
}

/**
 * Returns an AES-GCM AEAD using the Web Crypto API when available, and the
 * noble implementation otherwise.
 */
export async function aesGCM(key: Uint8Array): Promise<AEAD> {
    if (key.length !== 16 && key.length !== 32) {
        throw Error("invalid AES key size: " + key.length.toString())
    }
    const subtle = subtleCrypto()
    if (subtle === null) {
        return nobleAESGCM(key)
    }
    const cryptoKey = await subtle.importKey("raw", domBuffer(key), { name: "AES-GCM" }, false, ["encrypt", "decrypt"])
    return {
        async seal(nonce: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
            const algorithm = { name: "AES-GCM", iv: domBuffer(nonce) }
            return new Uint8Array(await subtle.encrypt(algorithm, cryptoKey, domBuffer(plaintext)))
        },
        async open(nonce: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
            const algorithm = { name: "AES-GCM", iv: domBuffer(nonce) }
            try {
                return new Uint8Array(await subtle.decrypt(algorithm, cryptoKey, domBuffer(ciphertext)))
            } catch (error) {
                if (error instanceof DOMException && error.name === "OperationError") {
                    throw Error("message authentication failed", { cause: error })
                }
                throw error
            }
        },
    }
}

function nobleAESGCM(key: Uint8Array): AEAD {
    return {
        seal(nonce: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
            return Promise.resolve(nobleBuffer(gcm(key, nonce).encrypt(plaintext)))
        },
        open(nonce: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
            try {
                return Promise.resolve(nobleBuffer(gcm(key, nonce).decrypt(ciphertext)))
            } catch (error) {
                return Promise.reject(Error("message authentication failed", { cause: error }))
            }
        },
    }
}

// noble allocates its outputs as plain Uint8Arrays over fresh ArrayBuffers,
// but declares them with the generic Uint8Array type.
function nobleBuffer(arr: Uint8Array): Uint8Array<ArrayBuffer> {
    return arr as Uint8Array<ArrayBuffer>
}

// TypeScript 5.9+ made Uint8Array generic, defaulting to Uint8Array<ArrayBufferLike>.
// DOM APIs like crypto.subtle require Uint8Array<ArrayBuffer> (no SharedArrayBuffer).
// This helper narrows the type while still catching non-Uint8Array arguments.
function domBuffer(arr: Uint8Array): Uint8Array<ArrayBuffer> {
    return arr as Uint8Array<ArrayBuffer>
}

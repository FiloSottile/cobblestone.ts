import { gcm } from "@noble/ciphers/aes.js"

export interface AEAD {
    seal(nonce: Uint8Array<ArrayBuffer>, plaintext: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>>
    open(nonce: Uint8Array<ArrayBuffer>, ciphertext: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>>
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
export async function aesGCM(key: Uint8Array<ArrayBuffer>): Promise<AEAD> {
    if (key.length !== 16 && key.length !== 32) {
        throw Error("invalid AES key size: " + key.length.toString())
    }
    const subtle = subtleCrypto()
    if (subtle === null) {
        return nobleAESGCM(key)
    }
    const cryptoKey = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt", "decrypt"])
    return {
        async seal(nonce: Uint8Array<ArrayBuffer>, plaintext: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
            const algorithm = { name: "AES-GCM", iv: nonce }
            return new Uint8Array(await subtle.encrypt(algorithm, cryptoKey, plaintext))
        },
        async open(nonce: Uint8Array<ArrayBuffer>, ciphertext: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
            const algorithm = { name: "AES-GCM", iv: nonce }
            try {
                return new Uint8Array(await subtle.decrypt(algorithm, cryptoKey, ciphertext))
            } catch (error) {
                if (error instanceof DOMException && error.name === "OperationError") {
                    throw Error("message authentication failed", { cause: error })
                }
                throw error
            }
        },
    }
}

function nobleAESGCM(key: Uint8Array<ArrayBuffer>): AEAD {
    return {
        seal(nonce: Uint8Array<ArrayBuffer>, plaintext: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
            return Promise.resolve(gcm(key, nonce).encrypt(plaintext))
        },
        open(nonce: Uint8Array<ArrayBuffer>, ciphertext: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
            try {
                return Promise.resolve(gcm(key, nonce).decrypt(ciphertext))
            } catch (error) {
                return Promise.reject(Error("message authentication failed", { cause: error }))
            }
        },
    }
}

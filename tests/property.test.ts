import { describe } from "vitest"
import { test, fc } from "@fast-check/vitest"
import { Decrypter, Encrypter, ciphertextSize, generateKey, plaintextSize } from "../lib/index.js"
import { chunkSize } from "../lib/chunked.js"
import { readAll } from "../lib/io.js"

fc.configureGlobal({
    // increasing this value will make fast-check do more random test runs,
    // which might be good for intensive testing, but also makes them slower.
    numRuns: typeof process !== "undefined" && process.env.SLOW ? 100 : 10,
})

const isEqualUInt8Array = (a: Uint8Array, b: Uint8Array) => {
    if (a.byteLength !== b.byteLength) {
        return false
    }

    for (let i = 0; i < a.byteLength; i++) {
        if (a[i] !== b[i]) {
            return false
        }
    }

    return true
}

describe("Property Based Tests", () => {
    describe("Encryption and Decryption", () => {
        test.prop(
            {
                plaintext: fc.string(),
                context: fc.string(),
            }
        )(
            "decryption should invert encryption (string plaintext)",
            async ({ plaintext, context }) => {
                const key = generateKey()
                const enc = new Encrypter(key, context)
                const dec = new Decrypter(key, context)
                const ciphertext = await enc.encrypt(new TextEncoder().encode(plaintext))
                return new TextDecoder().decode(await dec.decrypt(ciphertext)) === plaintext
            }
        )

        test.prop(
            {
                plaintext: fc.uint8Array({ maxLength: 2 * chunkSize + 100 }),
                context: fc.uint8Array(),
            }
        )(
            "decryption should invert encryption (uint8array plaintext)",
            async ({ plaintext, context }) => {
                const key = generateKey()
                const enc = new Encrypter(key, context)
                const dec = new Decrypter(key, context)
                const ciphertext = await enc.encrypt(plaintext)
                return ciphertext.length === ciphertextSize(plaintext.length) &&
                    plaintextSize(ciphertext.length) === plaintext.length &&
                    isEqualUInt8Array(await dec.decrypt(ciphertext), plaintext)
            }
        )

        test.prop(
            {
                plaintext: fc.uint8Array({ maxLength: 2 * chunkSize + 100 }),
                offset: fc.nat(),
                length: fc.nat(),
            }
        )(
            "random access reads should match the plaintext",
            async ({ plaintext, offset, length }) => {
                offset = offset % (plaintext.length + 1)
                const key = generateKey()
                const enc = new Encrypter(key)
                const dec = new Decrypter(key)
                const ciphertext = await enc.encrypt(plaintext)
                const r = await dec.decryptBlob(new Blob([ciphertext]))
                return r.size === plaintext.length &&
                    isEqualUInt8Array(await r.slice(offset, offset + length).bytes(), plaintext.subarray(offset, offset + length)) &&
                    isEqualUInt8Array(await readAll(r.slice(offset, offset + length).stream()), plaintext.subarray(offset, offset + length))
            }
        )
    })
})

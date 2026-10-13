import { test } from "vitest"
import { randomBytes } from "@noble/hashes/utils.js"
import { aesGCM, forceWebCryptoOff } from "../lib/aesgcm.js"
import { chunkSize, decryptChunks, encryptChunks } from "../lib/chunked.js"
import { readAll, stream } from "../lib/io.js"

const key = randomBytes(16)
const baseNonce = randomBytes(12)
const plaintext = new Uint8Array(64 * chunkSize)

const webCrypto = await aesGCM(key)
forceWebCryptoOff(true)
const noble = await aesGCM(key)
forceWebCryptoOff(false)

const ciphertext = await readAll(stream(plaintext).pipeThrough(new TransformStream(encryptChunks(webCrypto, baseNonce))))

test("encrypt 1 MiB", async ({ bench }) => {
    await bench.compare(
        bench("webcrypto", async () => {
            await readAll(stream(plaintext).pipeThrough(new TransformStream(encryptChunks(webCrypto, baseNonce))))
        }),
        bench("noble", async () => {
            await readAll(stream(plaintext).pipeThrough(new TransformStream(encryptChunks(noble, baseNonce))))
        }),
    )
})

test("decrypt 1 MiB", async ({ bench }) => {
    await bench.compare(
        bench("webcrypto", async () => {
            await readAll(stream(ciphertext).pipeThrough(new TransformStream(decryptChunks(webCrypto, baseNonce))))
        }),
        bench("noble", async () => {
            await readAll(stream(ciphertext).pipeThrough(new TransformStream(decryptChunks(noble, baseNonce))))
        }),
    )
})

import { EncryptionStream, DecryptionStream, Decrypter, generateKey, ciphertextSize, plaintextSize } from "cobblestone-encryption"

const key = generateKey()
const file = new File([new TextEncoder().encode("Hello, Cobblestone!")], "hello.txt")

const encryptedStream = file.stream().pipeThrough(new EncryptionStream(key, "example context"))
console.log(ciphertextSize(file.size))

const encrypted = new Uint8Array(await new Response(encryptedStream).arrayBuffer())
console.log(encrypted.length, plaintextSize(encrypted.length))

const decryptedStream = new Blob([encrypted]).stream().pipeThrough(new DecryptionStream(key, "example context"))
console.log(await new Response(decryptedStream).text())

const d = new Decrypter(key, "example context")
const plaintext = await d.decryptBlob(new Blob([encrypted]))
console.log(plaintext.size, new TextDecoder().decode(await plaintext.slice(7, 18).bytes()))
console.log(await new Response(plaintext.slice(-1).stream()).text())

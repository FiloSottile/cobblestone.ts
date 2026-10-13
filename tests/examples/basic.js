import * as cobblestone from "cobblestone-encryption"

const key = cobblestone.generateKey()

const e = new cobblestone.Encrypter(key, "example context")
const ciphertext = await e.encrypt(new TextEncoder().encode("Hello, Cobblestone!"))
console.log(ciphertext.length)

const d = new cobblestone.Decrypter(key, "example context")
const out = new TextDecoder().decode(await d.decrypt(ciphertext))
console.log(out)

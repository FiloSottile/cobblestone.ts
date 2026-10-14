// Cross-implementation tests against filippo.io/cobblestone (Go) and
// pyca/cryptography (Python). They are skipped if the implementations are
// not available, unless the INTEROP environment variable is set.

import { describe, it, assert, expect, beforeAll } from "vitest"
import { randomBytes } from "@noble/hashes/utils.js"
import { hex } from "@scure/base"
import { Decrypter, Encrypter, generateKey } from "../lib/index.js"
import { chunkSize } from "../lib/chunked.js"

const isNode = expect.getState().environment === "node"
const mustRun = typeof process !== "undefined" && process.env.INTEROP !== undefined

type Operation = "encrypt" | "decrypt"

interface Implementation {
    name: string
    available: () => Promise<boolean>
    // prepare does slow one-time setup, like compiling a helper.
    prepare?: () => Promise<void>
    run: (op: Operation, key: Uint8Array, context: Uint8Array, input: Uint8Array) => Promise<Uint8Array<ArrayBuffer>>
}

async function exec(file: string, args: string[], input: Uint8Array, cwd?: string): Promise<Uint8Array<ArrayBuffer>> {
    const { execFileSync } = await import("node:child_process")
    try {
        return new Uint8Array(execFileSync(file, args, {
            input, cwd, stdio: "pipe", maxBuffer: 64 * 1024 * 1024,
        }))
    } catch (error) {
        const stderr = (error as { stderr?: Buffer }).stderr?.toString() ?? ""
        throw Error(file + " " + args.join(" ") + " failed: " + stderr.trim(), { cause: error })
    }
}

async function canExec(file: string, args: string[], cwd?: string): Promise<boolean> {
    const { execFileSync } = await import("node:child_process")
    try {
        execFileSync(file, args, { cwd, stdio: "ignore" })
        return true
    } catch {
        return false
    }
}

// __dirname is only defined in Node.js, where these tests run.
const dirname = typeof __dirname === "undefined" ? "." : __dirname
const goDir = dirname + "/interop/go"
const python = (typeof process !== "undefined" ? process.env.PYTHON : undefined) ?? "python3"
const pythonScript = dirname + "/interop/interop.py"

const implementations: Implementation[] = [
    {
        name: "filippo.io/cobblestone",
        available: () => canExec("go", ["version"]),
        // The first go run downloads and compiles the module, which can
        // take longer than the test timeout.
        prepare: async () => {
            await exec("go", ["build", "-o", "/dev/null", "."], new Uint8Array(0), goDir)
        },
        run: (op, key, context, input) => exec("go",
            ["run", ".", op, hex.encode(key), hex.encode(context)], input, goDir),
    },
    {
        name: "pyca/cryptography",
        available: () => canExec(python, ["-I", "-c", "import cryptography.cobblestone"]),
        run: (op, key, context, input) => exec(python,
            ["-I", pythonScript, op, hex.encode(key), hex.encode(context)], input),
    },
]

describe.skipIf(!isNode)("interoperability", function () {
    for (const impl of implementations) {
        describe(impl.name, async function () {
            const available = await impl.available()
            if (!available && mustRun) {
                throw Error(impl.name + " is not available, but INTEROP is set")
            }
            const itIfAvailable = available ? it : it.skip
            if (available && impl.prepare !== undefined) {
                beforeAll(impl.prepare, 5 * 60 * 1000)
            }

            const context = new TextEncoder().encode("interop test")
            itIfAvailable.for([0, 1, 100, chunkSize, chunkSize + 1, 2 * chunkSize + 500])(
                "should round-trip %s bytes", async function (length) {
                    const key = generateKey()
                    const plaintext = randomBytes(length)

                    const theirs = await impl.run("encrypt", key, context, plaintext)
                    const d = new Decrypter(key, context)
                    assert.deepEqual(await d.decrypt(theirs), plaintext)
                    const r = await d.decryptBlob(new Blob([theirs]))
                    assert.deepEqual(await r.bytes(), plaintext)

                    const e = new Encrypter(key, context)
                    const ours = await e.encrypt(plaintext)
                    assert.equal(ours.length, theirs.length)
                    assert.deepEqual(await impl.run("decrypt", key, context, ours), plaintext)
                })
            itIfAvailable("should round-trip with an empty context", async function () {
                const key = generateKey()
                const plaintext = randomBytes(1000)
                const theirs = await impl.run("encrypt", key, new Uint8Array(0), plaintext)
                assert.deepEqual(await new Decrypter(key).decrypt(theirs), plaintext)
                const ours = await new Encrypter(key).encrypt(plaintext)
                assert.deepEqual(await impl.run("decrypt", key, new Uint8Array(0), ours), plaintext)
            })
            itIfAvailable("should reject our ciphertext with the wrong context", async function () {
                const key = generateKey()
                const ours = await new Encrypter(key, context).encrypt(new TextEncoder().encode("cobblestone"))
                await expect(impl.run("decrypt", key, new Uint8Array(0), ours)).rejects.toThrow()
            })
        })
    }
})

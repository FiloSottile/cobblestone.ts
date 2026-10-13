/**
 * The subset of the
 * {@link https://developer.mozilla.org/en-US/docs/Web/API/Blob | Blob}
 * interface that random access decryption reads from. A Blob (or File) can be
 * used directly, and custom implementations (for example backed by HTTP Range
 * requests) only need to implement `size` and `slice`.
 */
export interface Sliceable {
    /**
     * The total size of the data, in bytes.
     */
    readonly size: number

    /**
     * Returns the bytes between `start` (inclusive) and `end` (exclusive),
     * as an object with an `arrayBuffer` method, like
     * {@link https://developer.mozilla.org/en-US/docs/Web/API/Blob/slice | Blob.slice}.
     *
     * It is only ever called with `0 <= start <= end <= size`, and
     * `arrayBuffer` must resolve to exactly `end - start` bytes.
     *
     * @param start - The index of the first byte to read.
     * @param end - The index after the last byte to read.
     */
    slice(start: number, end: number): {
        /**
         * Reads the bytes of the range.
         */
        arrayBuffer(): Promise<ArrayBuffer>
    }
}

/**
 * A lazily decrypted message, as returned by `Decrypter.decryptBlob`. It has
 * the same shape as a
 * {@link https://developer.mozilla.org/en-US/docs/Web/API/Blob | Blob}:
 * the contents are only decrypted when read with
 * {@link DecryptedBlob.arrayBuffer}, {@link DecryptedBlob.bytes}, or
 * {@link DecryptedBlob.stream}, and {@link DecryptedBlob.slice} returns a
 * view of a range without reading it. Chunks are decrypted and
 * authenticated as they are read, and only the most recently read one is
 * cached. The final chunk is the exception: it's decrypted up front, to
 * authenticate the size of the message.
 */
export interface DecryptedBlob extends Sliceable {
    /**
     * Returns a DecryptedBlob of the bytes between `start` (inclusive) and
     * `end` (exclusive), with the same semantics as
     * {@link https://developer.mozilla.org/en-US/docs/Web/API/Blob/slice | Blob.slice}:
     * negative indexes count from the end, and out of range indexes are
     * clamped.
     *
     * @param start - The index of the first byte of the range. Defaults to 0.
     * @param end - The index after the last byte of the range. Defaults to
     * {@link Sliceable.size}.
     */
    slice(start?: number, end?: number): DecryptedBlob

    /**
     * Reads the whole contents as an ArrayBuffer.
     */
    arrayBuffer(): Promise<ArrayBuffer>

    /**
     * Reads the whole contents as a Uint8Array.
     */
    bytes(): Promise<Uint8Array<ArrayBuffer>>

    /**
     * Returns a ReadableStream of the contents.
     */
    stream(): ReadableStream<Uint8Array<ArrayBuffer>>
}

export function checkBytes(value: unknown, name: string): asserts value is Uint8Array {
    // Checked by brand rather than with instanceof, so that Uint8Arrays from
    // other realms (e.g. iframes) are accepted.
    if (!ArrayBuffer.isView(value) || Object.prototype.toString.call(value) !== "[object Uint8Array]") {
        throw TypeError(name + " must be a Uint8Array")
    }
}

// copyBytes returns an owned copy of src, as a plain Uint8Array over its own
// ArrayBuffer, so that later changes to src can't affect it. Note that
// Buffer.prototype.slice, unlike Uint8Array.prototype.slice, returns a view
// rather than a copy.
export function copyBytes(src: Uint8Array): Uint8Array<ArrayBuffer> {
    return new Uint8Array(src)
}

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
    return crypto.getRandomValues(new Uint8Array(n))
}

export function section(src: Sliceable, offset: number): Sliceable {
    return {
        size: src.size - offset,
        slice: (start: number, end: number) => src.slice(offset + start, offset + end),
    }
}

export async function readRange(src: Sliceable, start: number, end: number): Promise<Uint8Array<ArrayBuffer>> {
    const buffer: unknown = await src.slice(start, end).arrayBuffer()
    // Checked by brand rather than with instanceof, so that ArrayBuffers from
    // other realms (e.g. iframes) are accepted.
    if (Object.prototype.toString.call(buffer) !== "[object ArrayBuffer]") {
        throw TypeError("Sliceable.slice().arrayBuffer() must resolve to an ArrayBuffer")
    }
    const data = new Uint8Array(buffer as ArrayBuffer)
    if (data.length !== end - start) {
        throw Error((data.length < end - start ? "unexpected EOF" : "unexpected data") + ": read " +
            data.length.toString() + " bytes at offset " + start.toString() + ", want " + (end - start).toString())
    }
    return data
}

export function flatten(arr: Uint8Array[]): Uint8Array<ArrayBuffer> {
    const len = arr.reduce(((sum, line) => sum + line.length), 0)
    const out = new Uint8Array(len)
    let n = 0
    for (const a of arr) {
        out.set(a, n)
        n += a.length
    }
    return out
}

export function stream(a: Uint8Array): ReadableStream<Uint8Array> {
    // https://developer.mozilla.org/en-US/docs/Web/API/ReadableStream/from_static
    return new ReadableStream({
        start(controller) {
            controller.enqueue(a)
            controller.close()
        }
    })
}

// readAll uses a reader rather than new Response(stream).arrayBuffer()
// because some browsers (Firefox) replace stream errors with a generic
// AbortError when consuming a Response body.
export async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array<ArrayBuffer>> {
    if (!(stream instanceof ReadableStream)) {
        throw new Error("readAll expects a ReadableStream<Uint8Array>")
    }
    const reader = stream.getReader()
    const chunks: Uint8Array[] = []
    for (; ;) {
        const { done, value } = await reader.read()
        if (done) break
        chunks.push(value)
    }
    return flatten(chunks)
}

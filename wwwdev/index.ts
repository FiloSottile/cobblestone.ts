// Not using "cobblestone-encryption" to load the TS files directly.
import * as cobblestone from "../lib/index.js"
// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any
(globalThis as any).cobblestone = cobblestone

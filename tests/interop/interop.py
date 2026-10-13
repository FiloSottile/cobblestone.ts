"""Encrypts or decrypts standard input with pyca/cryptography, for
cross-implementation tests.

Usage: python3 interop.py encrypt|decrypt <hex key> <hex context>
"""

import sys

from cryptography.cobblestone import (
    Cobblestone128Decryptor,
    Cobblestone128Encryptor,
)


def main() -> None:
    if len(sys.argv) != 4:
        sys.exit("usage: interop.py encrypt|decrypt <hex key> <hex context>")
    op, key, context = sys.argv[1], bytes.fromhex(sys.argv[2]), bytes.fromhex(sys.argv[3])
    data = sys.stdin.buffer.read()
    if op == "encrypt":
        encryptor = Cobblestone128Encryptor(key, context)
        out = encryptor.update(data) + encryptor.finalize()
    elif op == "decrypt":
        decryptor = Cobblestone128Decryptor(key, context)
        out = decryptor.update(data) + decryptor.finalize()
    else:
        sys.exit(f"unknown operation {op!r}")
    sys.stdout.buffer.write(out)


if __name__ == "__main__":
    main()

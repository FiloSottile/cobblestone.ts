// Command interop encrypts or decrypts standard input with
// filippo.io/cobblestone, for cross-implementation tests.
//
// Usage: go run . encrypt|decrypt <hex key> <hex context>
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"filippo.io/cobblestone"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("usage: interop encrypt|decrypt <hex key> <hex context>")
	}
	key, err := hex.DecodeString(os.Args[2])
	if err != nil {
		return err
	}
	context, err := hex.DecodeString(os.Args[3])
	if err != nil {
		return err
	}
	switch os.Args[1] {
	case "encrypt":
		w, err := cobblestone.NewEncryptWriter(key, string(context), os.Stdout)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, os.Stdin); err != nil {
			return err
		}
		return w.Close()
	case "decrypt":
		r, err := cobblestone.NewDecryptReader(key, string(context), os.Stdin)
		if err != nil {
			return err
		}
		_, err = io.Copy(os.Stdout, r)
		return err
	default:
		return fmt.Errorf("unknown operation %q", os.Args[1])
	}
}

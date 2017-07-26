package tnt

import (
	"encoding/base64"
	"fmt"
	"os"
	"runtime/debug"
)

// HandlePanic when panic from somewhere
func HandlePanic() {
	if err := recover(); err != nil {
		fmt.Println("[FATAL]", err)
		fmt.Fprintln(os.Stderr, string(debug.Stack()))
	}
}

// Base64Encode encode to base64
func Base64Encode(src []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(src))
}

// Base64Decode decode to base64
func Base64Decode(src []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(src))
}

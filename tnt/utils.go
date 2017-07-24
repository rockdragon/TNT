package tnt

import (
	"fmt"
	"os"
	"runtime/debug"
)

func HandlePanic() {
	if err := recover(); err != nil {
		fmt.Println("[FATAL]", err)
		fmt.Fprintln(os.Stderr, string(debug.Stack()))
	}
}

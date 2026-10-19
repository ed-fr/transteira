// Command envexample writes the documented .env.example file to standard output, generated
// from the variable listing of internal/config so that the file can never drift from the code.
//
// Usage: go run ./tools/envexample > .env.example
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/ed-fr/transteira/internal/config"
)

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}

// run writes the .env.example content to stdout and returns the process exit code.
func run(stdout, stderr io.Writer) int {
	if err := config.WriteEnvExample(stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "envexample: %v\n", err)
		return 1
	}
	return 0
}

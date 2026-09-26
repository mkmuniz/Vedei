// Command nadzor detects and validates sensitive data and leaked secrets.
package main

import "fmt"

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	fmt.Printf("nadzor %s\n", version)
}

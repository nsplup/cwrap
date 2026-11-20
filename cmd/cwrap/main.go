// cwrap 命令行主入口：分发到 internal/cli。
package main

import (
	"os"

	"cwrap/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}

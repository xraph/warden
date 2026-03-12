// Example: Warden as a Forge extension with API routes.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/xraph/forge"

	wardenext "github.com/xraph/warden/extension"
	"github.com/xraph/warden/store/memory"
)

func main() {
	s := memory.New()

	app := forge.New(
		forge.WithExtensions(
			wardenext.New(
				wardenext.WithStore(s),
			),
		),
	)

	if err := app.Start(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "warden: %v\n", err)
		os.Exit(1)
	}
}

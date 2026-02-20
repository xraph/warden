// Example: Warden as a Forge extension with API routes.
package main

import (
	"context"
	"log"
	"log/slog"

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
				wardenext.WithLogger(slog.Default()),
			),
		),
	)

	if err := app.Start(context.Background()); err != nil {
		log.Fatal(err)
	}
}

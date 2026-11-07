//go:build ui

package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

// Build web/ first. No Node.js toolchain is needed for a normal Go build.
//
//go:embed dist
var assets embed.FS

const Available = true

func Handler() http.Handler {
	files, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err)
	}
	return staticHandler(files)
}

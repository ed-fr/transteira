// Package web embeds the built web interface (the public and admin applications produced by
// `make web-build` in web/dist) into the Go binary. internal/httpserver serves it.
//
// dist/.gitkeep is committed so that the package compiles, and `go build`, `go vet` and
// `go test` run, on a checkout without a Node build; the server then answers with a fallback
// page. `make build` refuses to build a binary without the web interface.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built interface rooted at dist/: public/index.html, admin/index.html,
// assets/* and the root files (favicon.svg, robots.txt). It only holds .gitkeep when the web
// interface has not been built.
func Dist() fs.FS {
	return mustSub(dist, "dist")
}

// mustSub returns the subtree dir of fsys. fs.Sub only fails on an invalid path, a programming
// error with the constant path used by Dist.
func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

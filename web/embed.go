// Package web embeds the web UI assets so bgpd-core ships as a single binary.
package web

import "embed"

// FS contains index.html and any future static assets under web/.
//
//go:embed index.html
var FS embed.FS

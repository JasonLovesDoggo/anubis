// Package xess vendors a copy of Xess and makes it available at /.xess/xess.css
//
// This is intended to be used as a vendored package in other projects.
package xess

import (
	"embed"
	"fmt"
	"github.com/TecharoHQ/anubis/internal"
	"net/http"
	"path/filepath"

	"github.com/TecharoHQ/anubis"
)

//go:generate go tool github.com/a-h/templ/cmd/templ generate

var (
	//go:embed *.css static
	Static embed.FS

	URL = "/.within.website/x/xess/xess.css"
)

func init() {
	Mount(http.DefaultServeMux)

	if anubis.Version != "devel" {
		URL = filepath.Join(filepath.Dir(URL), "xess.min.css")
	}

	URL = URL + "?cachebuster=" + anubis.Version
}

// Mount registers the xess static file handlers on the given mux
func Mount(mux *http.ServeMux) {
	prefix := anubis.BasePrefix + "/.within.website/x/xess/"
	fmt.Println(anubis.BasePrefix)
	mux.Handle(prefix, internal.UnchangingCache(http.StripPrefix(prefix, http.FileServerFS(Static))))
}

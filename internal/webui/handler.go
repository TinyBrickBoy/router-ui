// Package webui serves the single-page operator dashboard.
//
// The HTML template is embedded from web/index.html at compile time.
// The only template variable is {{.APIKey}}, which is injected server-side
// so the browser JS can authenticate against the JSON API without requiring
// the operator to enter a key manually.
//
// Mount at the mux root:
//
//	mux.Handle("/", webui.New(apiKey, webFS))
package webui

import (
	"embed"
	"html/template"
	"net/http"
)

// Handler serves the web UI.
type Handler struct {
	tmpl   *template.Template
	apiKey string
}

// New parses the embedded index.html template and returns a ready Handler.
// fs must expose "index.html" (use the web.FS embed variable).
func New(apiKey string, fs embed.FS) (*Handler, error) {
	tmpl, err := template.ParseFS(fs, "index.html")
	if err != nil {
		return nil, err
	}
	return &Handler{tmpl: tmpl, apiKey: apiKey}, nil
}

// ServeHTTP responds to GET / (and any unmatched path) with the dashboard.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only serve the SPA for GET requests to "/" or unknown UI paths.
	// Everything else falls through to the API mux (handled by the parent mux).
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = h.tmpl.ExecuteTemplate(w, "index.html", map[string]string{
		"APIKey": h.apiKey,
	})
}

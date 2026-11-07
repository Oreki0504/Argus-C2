// Package webui provides the Console's static UI. It does not authenticate
// requests or mount browser APIs, and must not be attached to the Fleet listener.
package webui

import (
	"io/fs"
	"net/http"
	"regexp"
	"strings"
)

const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

var hashedAsset = regexp.MustCompile(`^assets/[A-Za-z0-9_-]+-[A-Za-z0-9_-]{6,}\.[A-Za-z0-9.]+$`)

func staticHandler(files fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "v1" || strings.HasPrefix(path, "v1/") {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if files == nil {
			http.Error(w, "Console UI is not included in this build", http.StatusServiceUnavailable)
			return
		}
		if path == "" {
			path = "index.html"
		}
		if !fs.ValidPath(path) {
			http.NotFound(w, r)
			return
		}
		if _, err := fs.Stat(files, path); err != nil {
			// Missing assets must not receive an HTML success response. Only
			// extensionless client-side routes receive the SPA document.
			if strings.HasPrefix(path, "assets/") || strings.Contains(path, ".") {
				http.NotFound(w, r)
				return
			}
			path = "index.html"
		}
		info, err := fs.Stat(files, path)
		if err != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
		if hashedAsset.MatchString(path) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeFileFS(w, r, files, path)
	})
}

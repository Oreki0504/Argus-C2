package strictjson

import (
	"mime"
	"strings"
)

// MediaType accepts JSON with optional UTF-8 parameters. It does not enable
// decoding of other encodings or JSON-like types such as text/json.
func MediaType(value string) bool {
	media, params, err := mime.ParseMediaType(value)
	if err != nil || media != "application/json" {
		return false
	}
	charset, ok := params["charset"]
	return !ok || strings.EqualFold(charset, "utf-8")
}

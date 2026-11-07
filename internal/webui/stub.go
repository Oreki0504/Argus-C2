//go:build !ui

package webui

import "net/http"

const Available = false

func Handler() http.Handler { return staticHandler(nil) }

package api

import (
	"net/http"
	"strings"

	"github.com/Resinat/Resin/internal/platform"
	"github.com/Resinat/Resin/internal/service"
	"github.com/Resinat/Resin/internal/subexport"
)

type inheritLeaseRequest struct {
	ParentAccount string `json:"parent_account"`
	NewAccount    string `json:"new_account"`
}

// NewTokenActionHandler returns the handler for token-path actions.
func NewTokenActionHandler(proxyToken string, cp *service.ControlPlaneService, apiMaxBodyBytes int64) http.Handler {
	if cp == nil {
		return http.NotFoundHandler()
	}

	mux := http.NewServeMux()
	mux.Handle("POST /{token}/api/v1/{platform}/actions/inherit-lease", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := PathParam(r, "token")
		if proxyToken != "" && token != proxyToken {
			http.NotFound(w, r)
			return
		}

		platformName := strings.TrimSpace(PathParam(r, "platform"))
		if platformName == "" {
			writeInvalidArgument(w, "platform: must be non-empty")
			return
		}

		var req inheritLeaseRequest
		if err := DecodeBody(r, &req); err != nil {
			writeDecodeBodyError(w, err)
			return
		}

		if err := cp.InheritLeaseByPlatformName(platformName, req.ParentAccount, req.NewAccount); err != nil {
			writeServiceError(w, err)
			return
		}

		WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	// Subscription export endpoint.
	mux.Handle("GET /{token}/sub", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := PathParam(r, "token")
		if proxyToken != "" && token != proxyToken {
			http.NotFound(w, r)
			return
		}

		q := r.URL.Query()
		platformName := strings.TrimSpace(q.Get("platform"))
		if platformName == "" {
			platformName = platform.DefaultPlatformName
		}
		formatStr := strings.TrimSpace(q.Get("format"))
		format := subexport.DetectFormat(formatStr, r.Header.Get("User-Agent"))

		params := subexport.ExportParams{
			PlatformName: platformName,
			Format:       format,
		}
		contentType, body, err := subexport.Export(params, cp.Pool)
		if err != nil {
			writeServiceError(w, err)
			return
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", "inline")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))

	return RequestBodyLimitMiddleware(apiMaxBodyBytes, mux)
}

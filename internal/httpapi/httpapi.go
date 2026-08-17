// Package httpapi exposes the webhook service over HTTP.
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"task039-webhook/internal/webhook"
)

// API wires a webhook.Service to HTTP endpoints.
type API struct {
	svc *webhook.Service
}

// New creates an API bound to the given service.
func New(svc *webhook.Service) *API { return &API{svc: svc} }

// Handler returns the HTTP handler for all routes.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("POST /downstream", a.setDownstream)
	mux.HandleFunc("POST /events", a.receive)
	mux.HandleFunc("GET /events", a.list)
	mux.HandleFunc("GET /events/{id}", a.get)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, webhook.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, webhook.ErrNoDownstream):
		status = http.StatusConflict
	case errors.Is(err, webhook.ErrEmptyID),
		errors.Is(err, webhook.ErrInvalidStatus):
		status = http.StatusBadRequest
	case errors.Is(err, webhook.ErrMissingSign),
		errors.Is(err, webhook.ErrBadSignature):
		status = http.StatusUnauthorized
	}
	writeJSON(w, status, map[string]any{"error": err.Error(), "status": status})
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) setDownstream(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求体不是合法 JSON", "status": http.StatusBadRequest})
		return
	}
	if req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "下游地址不能为空", "status": http.StatusBadRequest})
		return
	}
	a.svc.SetDownstream(req.URL)
	writeJSON(w, http.StatusOK, map[string]string{"url": req.URL})
}

func (a *API) receive(w http.ResponseWriter, r *http.Request) {
	payload, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "读取请求体失败", "status": http.StatusBadRequest})
		return
	}
	id := r.Header.Get("X-Webhook-Id")
	sig := r.Header.Get("X-Webhook-Signature")

	receipt, err := a.svc.Receive(id, sig, payload)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (a *API) get(w http.ResponseWriter, r *http.Request) {
	ev, err := a.svc.Get(r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	events, err := a.svc.List(status)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "total": len(events)})
}

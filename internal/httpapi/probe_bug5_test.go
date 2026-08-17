package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"task039-webhook/internal/webhook"
)

func TestProbeRejectsTrailingJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/downstream", bytes.NewBufferString(`{"url":"http://example.com"} trailing`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	New(webhook.New("probe-secret")).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 for trailing JSON, body=%s", rec.Code, rec.Body.Bytes())
	}
}

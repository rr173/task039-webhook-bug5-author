package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"task039-webhook/internal/webhook"
)

const apiSecret = "api-secret"

func signPayload(payload []byte) string {
	mac := hmac.New(sha256.New, []byte(apiSecret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func newTestAPI(t *testing.T, downstreamURL string) (*httptest.Server, *http.Client) {
	t.Helper()
	svc := webhook.New(apiSecret, webhook.WithBaseBackoff(time.Millisecond))
	if downstreamURL != "" {
		svc.SetDownstream(downstreamURL)
	}
	srv := httptest.NewServer(New(svc).Handler())
	return srv, srv.Client()
}

func postOK(t *testing.T, c *http.Client, base, path string, headers map[string]string, rawBody []byte) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(rawBody))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func okDownstream() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestHealthz(t *testing.T) {
	srv, c := newTestAPI(t, "")
	defer srv.Close()
	resp, err := c.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSetDownstream(t *testing.T) {
	srv, c := newTestAPI(t, "")
	defer srv.Close()
	body, _ := json.Marshal(map[string]string{"url": "http://example.com/hook"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/downstream", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["url"] != "http://example.com/hook" {
		t.Errorf("url=%v", out["url"])
	}
}

func TestSetDownstream_EmptyURL(t *testing.T) {
	srv, c := newTestAPI(t, "")
	defer srv.Close()
	body, _ := json.Marshal(map[string]string{"url": ""})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/downstream", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}

func TestReceive_NoDownstream_Conflict(t *testing.T) {
	srv, c := newTestAPI(t, "") // no downstream
	defer srv.Close()
	payload := []byte(`{"a":1}`)
	code, out := postOK(t, c, srv.URL, "/events", map[string]string{
		"X-Webhook-Id":        "E1",
		"X-Webhook-Signature": signPayload(payload),
	}, payload)
	if code != http.StatusConflict {
		t.Fatalf("code=%d want 409 body=%v", code, out)
	}
}

func TestReceive_MissingID_BadRequest(t *testing.T) {
	ds := okDownstream()
	defer ds.Close()
	srv, c := newTestAPI(t, ds.URL)
	defer srv.Close()
	payload := []byte(`{"a":1}`)
	code, _ := postOK(t, c, srv.URL, "/events", map[string]string{
		"X-Webhook-Signature": signPayload(payload),
	}, payload)
	if code != http.StatusBadRequest {
		t.Fatalf("code=%d want 400", code)
	}
}

func TestReceive_BadSignature_Unauthorized(t *testing.T) {
	ds := okDownstream()
	defer ds.Close()
	srv, c := newTestAPI(t, ds.URL)
	defer srv.Close()
	payload := []byte(`{"a":1}`)
	code, _ := postOK(t, c, srv.URL, "/events", map[string]string{
		"X-Webhook-Id":        "E1",
		"X-Webhook-Signature": "00",
	}, payload)
	if code != http.StatusUnauthorized {
		t.Fatalf("code=%d want 401", code)
	}
}

func TestReceive_Delivered(t *testing.T) {
	ds := okDownstream()
	defer ds.Close()
	srv, c := newTestAPI(t, ds.URL)
	defer srv.Close()
	payload := []byte(`{"event":"ok"}`)
	code, out := postOK(t, c, srv.URL, "/events", map[string]string{
		"X-Webhook-Id":        "E1",
		"X-Webhook-Signature": signPayload(payload),
	}, payload)
	if code != http.StatusOK {
		t.Fatalf("code=%d want 200 body=%v", code, out)
	}
	if out["status"] != "delivered" || out["attempts"] != float64(1) {
		t.Errorf("receipt=%v want delivered/1", out)
	}

	// GET the event back.
	resp, err := c.Get(srv.URL + "/events/E1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status=%d", resp.StatusCode)
	}
	var ev map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&ev)
	if ev["payload"] != string(payload) {
		t.Errorf("payload=%v want %s", ev["payload"], payload)
	}
}

func TestGet_NotFound(t *testing.T) {
	srv, c := newTestAPI(t, "")
	defer srv.Close()
	resp, err := c.Get(srv.URL + "/events/NOPE")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d want 404", resp.StatusCode)
	}
}

func TestList_BadStatusFilter(t *testing.T) {
	srv, c := newTestAPI(t, "")
	defer srv.Close()
	resp, err := c.Get(srv.URL + "/events?status=bogus")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}

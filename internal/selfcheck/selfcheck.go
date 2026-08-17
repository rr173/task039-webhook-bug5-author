// Package selfcheck runs an end-to-end verification of the webhook service
// against an in-process HTTP server plus a controllable downstream. It is
// invoked by the --smoke-test flag and exits the process on completion.
//
// Because the dedup store is global mutable state, each scenario builds its
// own fresh service+server+downstream so state never leaks between scenarios.
package selfcheck

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"task039-webhook/internal/httpapi"
	"task039-webhook/internal/webhook"
)

const testSecret = "test-secret"

// env bundles a fresh webhook server, client, and a downstream it controls.
type env struct {
	base string
	c    *http.Client
	srv  *httptest.Server
}

func newEnv() (*env, *flakyDownstream) {
	ds := &flakyDownstream{}
	dsSrv := httptest.NewServer(ds)
	svc := webhook.New(testSecret, webhook.WithBaseBackoff(20*time.Millisecond))
	api := httpapi.New(svc)
	srv := httptest.NewServer(api.Handler())
	e := &env{base: srv.URL, c: srv.Client(), srv: srv}
	// Register the downstream before any events.
	e.post("/downstream", map[string]any{"url": dsSrv.URL}, nil, nil)
	// Keep dsSrv alive for the scenario via the downstream struct.
	ds.closeSrv = dsSrv
	return e, ds
}

// envWithDownstream builds an env whose downstream is the given URL string
// (used for the unreachable-downstream scenario).
func newEnvWithURL(dsURL string) *env {
	svc := webhook.New(testSecret, webhook.WithBaseBackoff(20*time.Millisecond))
	api := httpapi.New(svc)
	srv := httptest.NewServer(api.Handler())
	e := &env{base: srv.URL, c: srv.Client(), srv: srv}
	e.post("/downstream", map[string]any{"url": dsURL}, nil, nil)
	return e
}

func (e *env) close() { e.srv.Close() }

// Run exercises the full HTTP API across isolated scenarios, returning nil if
// every behavior matches the specification.
func Run() error {
	scenarios := []struct {
		name string
		fn   func() error
	}{
		{"健康检查", scenarioHealth},
		{"未注册下游返回 409", scenarioNoDownstream},
		{"缺失事件 id 返回 400", scenarioMissingID},
		{"缺失签名返回 401", scenarioMissingSig},
		{"签名不匹配返回 401", scenarioBadSig},
		{"合法事件首次投递成功", scenarioDelivered},
		{"重复事件幂等不重投", scenarioDuplicate},
		{"重试两次后第三次成功", scenarioRetryThenSucceed},
		{"重试耗尽进入死信", scenarioExhausted},
		{"下游不可达触发重试至耗尽", scenarioUnreachable},
		{"查询事件状态与载荷", scenarioGet},
		{"查询不存在事件 404", scenarioNotFound},
		{"死信列表与全量列表", scenarioList},
		{"非法状态过滤值 400", scenarioBadStatusFilter},
	}
	for _, sc := range scenarios {
		if err := sc.fn(); err != nil {
			return fmt.Errorf("%s: %w", sc.name, err)
		}
	}
	return nil
}

// ---- HTTP helpers ----

func (e *env) post(path string, body any, headers map[string]string, rawBody []byte) (int, map[string]any, []byte) {
	var r io.Reader
	if rawBody != nil {
		r = bytes.NewReader(rawBody)
	} else if body != nil {
		buf, _ := json.Marshal(body)
		r = bytes.NewReader(buf)
	}
	req, _ := http.NewRequest(http.MethodPost, e.base+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.c.Do(req)
	if err != nil {
		return 0, nil, nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	return resp.StatusCode, out, data
}

func (e *env) get(path string) (int, map[string]any, []byte) {
	req, _ := http.NewRequest(http.MethodGet, e.base+path, nil)
	resp, err := e.c.Do(req)
	if err != nil {
		return 0, nil, nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	return resp.StatusCode, out, data
}

// sign computes the lowercase hex HMAC-SHA256 of payload under testSecret.
func sign(payload []byte) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// postEvent sends a signed POST /events with the given id and raw payload.
func (e *env) postEvent(id string, payload []byte) (int, map[string]any, []byte) {
	return e.post("/events", nil, map[string]string{
		"X-Webhook-Id":        id,
		"X-Webhook-Signature": sign(payload),
	}, payload)
}

// ---- downstream ----

// flakyDownstream is a controllable downstream that records every call and
// fails the first failFirst calls (HTTP 500) before succeeding.
type flakyDownstream struct {
	mu        sync.Mutex
	calls     int
	bodies    [][]byte
	ids       []string
	failFirst int
	closeSrv  *httptest.Server
}

func (f *flakyDownstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls++
	f.bodies = append(f.bodies, body)
	f.ids = append(f.ids, r.Header.Get("X-Webhook-Id"))
	n := f.calls
	f.mu.Unlock()
	if n <= f.failFirst {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (f *flakyDownstream) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *flakyDownstream) lastBody() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bodies) == 0 {
		return nil
	}
	return f.bodies[len(f.bodies)-1]
}

func (f *flakyDownstream) lastID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ids) == 0 {
		return ""
	}
	return f.ids[len(f.ids)-1]
}

// ---- scenarios ----

func scenarioHealth() error {
	e, _ := newEnv()
	defer e.close()
	code, body, _ := e.get("/healthz")
	if code != http.StatusOK || body["status"] != "ok" {
		return fmt.Errorf("healthz: code=%d body=%v", code, body)
	}
	return nil
}

func scenarioNoDownstream() error {
	// Build a service with NO downstream registered and send a valid event.
	svc := webhook.New(testSecret, webhook.WithBaseBackoff(20*time.Millisecond))
	srv := httptest.NewServer(httpapi.New(svc).Handler())
	defer srv.Close()
	e := &env{base: srv.URL, c: srv.Client(), srv: srv}
	payload := []byte(`{"x":1}`)
	code, body, _ := e.postEvent("E1", payload)
	if code != http.StatusConflict {
		return fmt.Errorf("no downstream: code=%d want 409 body=%v", code, body)
	}
	if body["error"] == nil {
		return fmt.Errorf("no downstream: missing error field: %v", body)
	}
	return nil
}

func scenarioMissingID() error {
	e, ds := newEnv()
	defer e.close()
	defer ds.closeSrv.Close()
	payload := []byte(`{"x":1}`)
	// Sign is valid, but X-Webhook-Id header is absent.
	code, body, _ := e.post("/events", nil, map[string]string{
		"X-Webhook-Signature": sign(payload),
	}, payload)
	if code != http.StatusBadRequest {
		return fmt.Errorf("missing id: code=%d want 400 body=%v", code, body)
	}
	if ds.count() != 0 {
		return fmt.Errorf("missing id: downstream called %d times, want 0", ds.count())
	}
	return nil
}

func scenarioMissingSig() error {
	e, ds := newEnv()
	defer e.close()
	defer ds.closeSrv.Close()
	payload := []byte(`{"x":1}`)
	code, body, _ := e.post("/events", nil, map[string]string{
		"X-Webhook-Id": "E2",
	}, payload)
	if code != http.StatusUnauthorized {
		return fmt.Errorf("missing sig: code=%d want 401 body=%v", code, body)
	}
	if ds.count() != 0 {
		return fmt.Errorf("missing sig: downstream called %d times, want 0", ds.count())
	}
	return nil
}

func scenarioBadSig() error {
	e, ds := newEnv()
	defer e.close()
	defer ds.closeSrv.Close()
	payload := []byte(`{"x":1}`)
	code, body, _ := e.post("/events", nil, map[string]string{
		"X-Webhook-Id":        "E3",
		"X-Webhook-Signature": "deadbeef",
	}, payload)
	if code != http.StatusUnauthorized {
		return fmt.Errorf("bad sig: code=%d want 401 body=%v", code, body)
	}
	if ds.count() != 0 {
		return fmt.Errorf("bad sig: downstream called %d times, want 0", ds.count())
	}
	return nil
}

func scenarioDelivered() error {
	e, ds := newEnv()
	defer e.close()
	defer ds.closeSrv.Close()
	payload := []byte(`{"event":"created","ref":"abc"}`)
	code, body, _ := e.postEvent("D1", payload)
	if code != http.StatusOK {
		return fmt.Errorf("delivered: code=%d body=%v", code, body)
	}
	if body["status"] != "delivered" || body["attempts"] != float64(1) {
		return fmt.Errorf("delivered: status=%v attempts=%v want delivered/1", body["status"], body["attempts"])
	}
	if ds.count() != 1 {
		return fmt.Errorf("delivered: downstream calls=%d want 1", ds.count())
	}
	if string(ds.lastBody()) != string(payload) {
		return fmt.Errorf("delivered: downstream body=%q want %q", ds.lastBody(), payload)
	}
	if ds.lastID() != "D1" {
		return fmt.Errorf("delivered: downstream X-Webhook-Id=%q want D1", ds.lastID())
	}
	return nil
}

func scenarioDuplicate() error {
	e, ds := newEnv()
	defer e.close()
	defer ds.closeSrv.Close()
	payload := []byte(`{"k":"v"}`)
	if code, _, _ := e.postEvent("DUP1", payload); code != http.StatusOK {
		return fmt.Errorf("dup first: code=%d", code)
	}
	before := ds.count()
	code, body, _ := e.postEvent("DUP1", payload)
	if code != http.StatusOK {
		return fmt.Errorf("dup second: code=%d", code)
	}
	if body["status"] != "duplicate" {
		return fmt.Errorf("dup second: status=%v want duplicate", body["status"])
	}
	if body["attempts"] != float64(1) {
		return fmt.Errorf("dup second: attempts=%v want 1", body["attempts"])
	}
	if ds.count() != before {
		return fmt.Errorf("dup second: downstream calls grew %d->%d", before, ds.count())
	}
	return nil
}

func scenarioRetryThenSucceed() error {
	e, ds := newEnv()
	defer e.close()
	defer ds.closeSrv.Close()
	ds.failFirst = 2 // first 2 calls return 500, 3rd succeeds.
	payload := []byte(`{"retry":true}`)
	code, body, _ := e.postEvent("R1", payload)
	if code != http.StatusOK {
		return fmt.Errorf("retry-ok: code=%d body=%v", code, body)
	}
	if body["status"] != "delivered" || body["attempts"] != float64(3) {
		return fmt.Errorf("retry-ok: status=%v attempts=%v want delivered/3", body["status"], body["attempts"])
	}
	if ds.count() != 3 {
		return fmt.Errorf("retry-ok: downstream calls=%d want 3", ds.count())
	}
	return nil
}

func scenarioExhausted() error {
	e, ds := newEnv()
	defer e.close()
	defer ds.closeSrv.Close()
	ds.failFirst = 1000 // always fail.
	payload := []byte(`{"fail":true}`)
	code, body, _ := e.postEvent("F1", payload)
	if code != http.StatusOK {
		return fmt.Errorf("exhausted: code=%d body=%v", code, body)
	}
	if body["status"] != "failed" || body["attempts"] != float64(3) {
		return fmt.Errorf("exhausted: status=%v attempts=%v want failed/3", body["status"], body["attempts"])
	}
	if ds.count() != 3 {
		return fmt.Errorf("exhausted: downstream calls=%d want 3", ds.count())
	}
	return nil
}

func scenarioUnreachable() error {
	// A closed httptest server: its listener is gone, so dialing refuses
	// the connection immediately — exercising the network-error retry path.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	e := newEnvWithURL(deadURL)
	defer e.close()
	payload := []byte(`{"net":true}`)
	code, body, _ := e.postEvent("U1", payload)
	if code != http.StatusOK {
		return fmt.Errorf("unreachable: code=%d body=%v", code, body)
	}
	if body["status"] != "failed" || body["attempts"] != float64(3) {
		return fmt.Errorf("unreachable: status=%v attempts=%v want failed/3", body["status"], body["attempts"])
	}
	// The failed event must be queryable and recorded.
	code, body, _ = e.get("/events/U1")
	if code != http.StatusOK || body["status"] != "failed" {
		return fmt.Errorf("unreachable get: code=%d body=%v", code, body)
	}
	return nil
}

func scenarioGet() error {
	e, _ := newEnv()
	defer e.close()
	payload := []byte(`{"q":42}`)
	if code, _, _ := e.postEvent("G1", payload); code != http.StatusOK {
		return fmt.Errorf("get: post code=%d", code)
	}
	code, body, _ := e.get("/events/G1")
	if code != http.StatusOK {
		return fmt.Errorf("get: code=%d body=%v", code, body)
	}
	if body["event_id"] != "G1" || body["status"] != "delivered" || body["attempts"] != float64(1) {
		return fmt.Errorf("get: body=%v want G1/delivered/1", body)
	}
	if body["payload"] != string(payload) {
		return fmt.Errorf("get: payload=%v want %s", body["payload"], payload)
	}
	if body["created_at"] == nil || body["updated_at"] == nil {
		return fmt.Errorf("get: missing timestamps: %v", body)
	}
	return nil
}

func scenarioNotFound() error {
	e, _ := newEnv()
	defer e.close()
	code, _, _ := e.get("/events/NOPE")
	if code != http.StatusNotFound {
		return fmt.Errorf("not found: code=%d want 404", code)
	}
	return nil
}

func scenarioList() error {
	e, ds := newEnv()
	defer e.close()
	defer ds.closeSrv.Close()
	// One delivered event, one failed event.
	if code, _, _ := e.postEvent("L1", []byte(`{"a":1}`)); code != http.StatusOK {
		return fmt.Errorf("list: L1 code=%d", code)
	}
	ds.failFirst = 1000
	if code, _, _ := e.postEvent("L2", []byte(`{"a":2}`)); code != http.StatusOK {
		return fmt.Errorf("list: L2 code=%d", code)
	}
	// Dead-letter list: only L2.
	code, body, _ := e.get("/events?status=failed")
	if code != http.StatusOK {
		return fmt.Errorf("list failed: code=%d", code)
	}
	if body["total"] != float64(1) {
		return fmt.Errorf("list failed: total=%v want 1", body["total"])
	}
	events, _ := body["events"].([]any)
	if len(events) != 1 {
		return fmt.Errorf("list failed: len=%d want 1", len(events))
	}
	first, _ := events[0].(map[string]any)
	if first["event_id"] != "L2" {
		return fmt.Errorf("list failed: event_id=%v want L2", first["event_id"])
	}
	// Full list: both, in creation order L1 then L2.
	code, body, _ = e.get("/events")
	if code != http.StatusOK || body["total"] != float64(2) {
		return fmt.Errorf("list all: code=%d total=%v want 2", code, body["total"])
	}
	events, _ = body["events"].([]any)
	if len(events) != 2 {
		return fmt.Errorf("list all: len=%d want 2", len(events))
	}
	e0, _ := events[0].(map[string]any)
	e1, _ := events[1].(map[string]any)
	if e0["event_id"] != "L1" || e1["event_id"] != "L2" {
		return fmt.Errorf("list all: order=%v,%v want L1,L2", e0["event_id"], e1["event_id"])
	}
	return nil
}

func scenarioBadStatusFilter() error {
	e, _ := newEnv()
	defer e.close()
	code, body, _ := e.get("/events?status=bogus")
	if code != http.StatusBadRequest {
		return fmt.Errorf("bad filter: code=%d want 400 body=%v", code, body)
	}
	return nil
}

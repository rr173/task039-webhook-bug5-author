package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const testSecret = "unit-secret"

func sign(t *testing.T, payload []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// flakyDS fails the first failFirst calls then succeeds.
type flakyDS struct {
	mu        sync.Mutex
	calls     int
	failFirst int
}

func (f *flakyDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()
	if n <= f.failFirst {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (f *flakyDS) callsCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestReceive_InvalidSignature(t *testing.T) {
	ds := &flakyDS{}
	srv := httptest.NewServer(ds)
	defer srv.Close()
	s := New(testSecret, WithBaseBackoff(time.Millisecond))
	s.SetDownstream(srv.URL)

	payload := []byte(`{"a":1}`)
	for _, tc := range []struct {
		name string
		id   string
		sig  string
		want error
	}{
		{"empty id", "", sign(t, payload), ErrEmptyID},
		{"missing sig", "E1", "", ErrMissingSign},
		{"bad sig", "E1", "deadbeef", ErrBadSignature},
	} {
		_, err := s.Receive(tc.id, tc.sig, payload)
		if err != tc.want {
			t.Errorf("%s: err=%v want %v", tc.name, err, tc.want)
		}
	}
	if got := ds.callsCount(); got != 0 {
		t.Errorf("downstream called %d times on bad input, want 0", got)
	}
}

func TestReceive_NoDownstream(t *testing.T) {
	s := New(testSecret)
	payload := []byte(`{"a":1}`)
	_, err := s.Receive("E1", sign(t, payload), payload)
	if err != ErrNoDownstream {
		t.Errorf("err=%v want ErrNoDownstream", err)
	}
}

func TestReceive_Delivered(t *testing.T) {
	ds := &flakyDS{}
	srv := httptest.NewServer(ds)
	defer srv.Close()
	s := New(testSecret, WithBaseBackoff(time.Millisecond))
	s.SetDownstream(srv.URL)

	payload := []byte(`{"event":"x"}`)
	r, err := s.Receive("D1", sign(t, payload), payload)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if r.Status != StatusDelivered || r.Attempts != 1 {
		t.Errorf("receipt=%+v want delivered/1", r)
	}
	if got := ds.callsCount(); got != 1 {
		t.Errorf("downstream calls=%d want 1", got)
	}
	ev, err := s.Get("D1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ev.Status != StatusDelivered || ev.Attempts != 1 {
		t.Errorf("event=%+v want delivered/1", ev)
	}
	if string(ev.Payload) != string(payload) {
		t.Errorf("payload=%q want %q", ev.Payload, payload)
	}
}

func TestReceive_DuplicateNotRedelivered(t *testing.T) {
	ds := &flakyDS{}
	srv := httptest.NewServer(ds)
	defer srv.Close()
	s := New(testSecret, WithBaseBackoff(time.Millisecond))
	s.SetDownstream(srv.URL)

	payload := []byte(`{"k":1}`)
	if _, err := s.Receive("DUP", sign(t, payload), payload); err != nil {
		t.Fatalf("first Receive: %v", err)
	}
	r, err := s.Receive("DUP", sign(t, payload), payload)
	if err != nil {
		t.Fatalf("second Receive: %v", err)
	}
	if r.Status != StatusDuplicate || r.Attempts != 1 {
		t.Errorf("receipt=%+v want duplicate/1", r)
	}
	if got := ds.callsCount(); got != 1 {
		t.Errorf("downstream calls=%d want 1 (no redelivery)", got)
	}
}

func TestReceive_RetryThenSucceed(t *testing.T) {
	ds := &flakyDS{failFirst: 2}
	srv := httptest.NewServer(ds)
	defer srv.Close()
	s := New(testSecret, WithBaseBackoff(time.Millisecond))
	s.SetDownstream(srv.URL)

	r, err := s.Receive("R1", sign(t, []byte(`{}`)), []byte(`{}`))
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if r.Status != StatusDelivered || r.Attempts != 3 {
		t.Errorf("receipt=%+v want delivered/3", r)
	}
	if got := ds.callsCount(); got != 3 {
		t.Errorf("downstream calls=%d want 3", got)
	}
}

func TestReceive_ExhaustedDeadLetter(t *testing.T) {
	ds := &flakyDS{failFirst: 1000}
	srv := httptest.NewServer(ds)
	defer srv.Close()
	s := New(testSecret, WithBaseBackoff(time.Millisecond), WithMaxAttempts(3))
	s.SetDownstream(srv.URL)

	r, err := s.Receive("F1", sign(t, []byte(`{}`)), []byte(`{}`))
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if r.Status != StatusFailed || r.Attempts != 3 {
		t.Errorf("receipt=%+v want failed/3", r)
	}
	if got := ds.callsCount(); got != 3 {
		t.Errorf("downstream calls=%d want 3", got)
	}
	// The failed event is queryable and carries the last error.
	ev, err := s.Get("F1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ev.Status != StatusFailed || ev.LastError == "" {
		t.Errorf("event=%+v want failed with last_error", ev)
	}
}

func TestReceive_UnreachableDownstream(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	s := New(testSecret, WithBaseBackoff(time.Millisecond), WithMaxAttempts(3))
	s.SetDownstream(deadURL)

	r, err := s.Receive("U1", sign(t, []byte(`{}`)), []byte(`{}`))
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if r.Status != StatusFailed || r.Attempts != 3 {
		t.Errorf("receipt=%+v want failed/3", r)
	}
}

func TestList_FilterAndOrder(t *testing.T) {
	ds := &flakyDS{failFirst: 1000}
	srv := httptest.NewServer(ds)
	defer srv.Close()
	s := New(testSecret, WithBaseBackoff(time.Millisecond), WithMaxAttempts(3))
	s.SetDownstream(srv.URL)

	// L1 delivered, L2 failed, L3 delivered.
	mk := func(id string, payload []byte) {
		t.Helper()
		if _, err := s.Receive(id, sign(t, payload), payload); err != nil {
			t.Fatalf("Receive %s: %v", id, err)
		}
	}
	// First event delivered (ds succeeds since failFirst resets per-call? No:
	// failFirst is global on the counter). Reset by using a fresh downstream
	// for delivered ones.
	ds2 := &flakyDS{}
	srv2 := httptest.NewServer(ds2)
	defer srv2.Close()

	s.SetDownstream(srv2.URL)
	mk("L1", []byte(`{"1":true}`))
	mk("L3", []byte(`{"3":true}`))
	// Now point at the always-failing server and send L2.
	s.SetDownstream(srv.URL)
	mk("L2", []byte(`{"2":true}`))

	all, err := s.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("List all len=%d want 3", len(all))
	}
	// Creation order: L1, L3, L2.
	wantOrder := []string{"L1", "L3", "L2"}
	for i, w := range wantOrder {
		if all[i].ID != w {
			t.Errorf("order[%d]=%s want %s", i, all[i].ID, w)
		}
	}

	failed, err := s.List(StatusFailed)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(failed) != 1 || failed[0].ID != "L2" {
		t.Errorf("failed list=%+v want [L2]", failed)
	}

	delivered, err := s.List(StatusDelivered)
	if err != nil {
		t.Fatalf("List delivered: %v", err)
	}
	if len(delivered) != 2 {
		t.Errorf("delivered list len=%d want 2", len(delivered))
	}

	if _, err := s.List("bogus"); err != ErrInvalidStatus {
		t.Errorf("List bogus err=%v want ErrInvalidStatus", err)
	}
}

// Package webhook implements a Webhook receiver that verifies HMAC-SHA256
// signatures, deduplicates events by id, and synchronously delivers the raw
// payload to a registered downstream URL with exponential-backoff retry.
//
// Delivery is inline: a call to Receive blocks until the payload has been
// delivered (2xx from downstream) or the retry budget is exhausted, in which
// case the event is recorded as failed (dead-letter) and never retried again.
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Delivery and event status values.
const (
	StatusDelivering = "delivering" // in-flight (delivery not yet finished)
	StatusDelivered  = "delivered"  // downstream returned 2xx
	StatusFailed     = "failed"     // retry budget exhausted; dead-letter
	StatusDuplicate  = "duplicate"  // POST response only: id already seen
)

// Default retry tuning.
const (
	defaultMaxAttempts = 3
	defaultBaseBackoff = 50 * time.Millisecond
)

// Errors returned by the service. The HTTP layer maps these to status codes.
var (
	ErrEmptyID       = errors.New("事件编号不能为空")
	ErrMissingSign   = errors.New("缺少签名头")
	ErrBadSignature  = errors.New("签名校验失败")
	ErrNoDownstream  = errors.New("未注册下游投递地址")
	ErrNotFound      = errors.New("事件不存在")
	ErrInvalidStatus = errors.New("状态过滤值非法")
)

// Event is the stored delivery record for one webhook event id.
type Event struct {
	ID        string    `json:"event_id"`
	Payload   []byte    `json:"-"`
	PayloadS  string    `json:"payload"`
	Status    string    `json:"status"`
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// seq is a monotonic insertion counter used for stable creation-order
	// sorting independent of clock resolution. Never serialized.
	seq int64 `json:"-"`
}

// Receipt is the synchronous answer to a POST /events request.
type Receipt struct {
	EventID  string `json:"event_id"`
	Status   string `json:"status"`
	Attempts int    `json:"attempts"`
}

// Service holds the dedup store, downstream target, and delivery client.
type Service struct {
	secret        string
	maxAttempts   int
	baseBackoff   time.Duration
	client        *http.Client
	now           func() time.Time

	mu             sync.Mutex
	events         map[string]*Event
	downstreamURL  string
	nextSeq        int64
}

// Option configures a Service.
type Option func(*Service)

// WithMaxAttempts overrides the max delivery attempts (including the first).
func WithMaxAttempts(n int) Option {
	return func(s *Service) { if n > 0 { s.maxAttempts = n } }
}

// WithBaseBackoff overrides the exponential-backoff base delay.
func WithBaseBackoff(d time.Duration) Option {
	return func(s *Service) { if d > 0 { s.baseBackoff = d } }
}

// WithClient overrides the HTTP client used for downstream delivery.
func WithClient(c *http.Client) Option {
	return func(s *Service) { if c != nil { s.client = c } }
}

// WithClock overrides the time source for CreatedAt/UpdatedAt.
func WithClock(now func() time.Time) Option {
	return func(s *Service) { if now != nil { s.now = now } }
}

// New creates a Service bound to the given shared HMAC secret.
func New(secret string, opts ...Option) *Service {
	s := &Service{
		secret:      secret,
		maxAttempts: defaultMaxAttempts,
		baseBackoff: defaultBaseBackoff,
		client: &http.Client{
			Timeout: 2 * time.Second,
		},
		now:    time.Now,
		events: make(map[string]*Event),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// SetDownstream registers (or replaces) the downstream delivery URL.
func (s *Service) SetDownstream(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.downstreamURL = url
}

// Downstream returns the currently registered downstream URL (empty if none).
func (s *Service) Downstream() string {
	return s.downstreamURL
}

// Receive verifies the signature, deduplicates by id, and synchronously
// delivers the payload with retry. It returns a Receipt describing the
// outcome (delivered / failed / duplicate).
func (s *Service) Receive(id, sigHex string, payload []byte) (Receipt, error) {
	if strings.TrimSpace(id) == "" {
		return Receipt{}, ErrEmptyID
	}
	if sigHex == "" {
		return Receipt{}, ErrMissingSign
	}
	want := hexSig(s.secret, payload)
	if !secureEqual(sigHex, want) {
		return Receipt{}, ErrBadSignature
	}

	s.mu.Lock()
	if s.downstreamURL == "" {
		s.mu.Unlock()
		return Receipt{}, ErrNoDownstream
	}
	if ev, ok := s.events[id]; ok {
		s.mu.Unlock()
		return Receipt{EventID: id, Status: StatusDuplicate, Attempts: ev.Attempts}, nil
	}
	now := s.now()
	ev := &Event{
		ID:        id,
		Payload:   payload,
		Status:    StatusDelivering,
		CreatedAt: now,
		UpdatedAt: now,
		seq:       s.nextSeq,
	}
	s.nextSeq++
	s.events[id] = ev
	url := s.downstreamURL
	s.mu.Unlock()

	attempts, delivered, lastErr := s.deliver(url, id, payload)

	s.mu.Lock()
	ev.Attempts = attempts
	if delivered {
		ev.Status = StatusDelivered
		ev.LastError = ""
	} else {
		ev.Status = StatusFailed
		ev.LastError = lastErr
	}
	ev.UpdatedAt = s.now()
	s.mu.Unlock()

	return Receipt{EventID: id, Status: ev.Status, Attempts: attempts}, nil
}

// Get returns a snapshot of the event with the given id.
func (s *Service) Get(id string) (*Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev, ok := s.events[id]
	if !ok {
		return nil, ErrNotFound
	}
	return ev.clone(), nil
}

// List returns events in creation order, optionally filtered by status.
// An empty status returns all events.
func (s *Service) List(status string) ([]*Event, error) {
	if status != "" && status != StatusDelivered && status != StatusFailed && status != StatusDelivering {
		return nil, ErrInvalidStatus
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Event
	for _, ev := range s.events {
		if status != "" && ev.Status != status {
			continue
		}
		out = append(out, ev.clone())
	}
	// Stable ascending creation order via the monotonic sequence counter.
	sortBySeq(out)
	return out, nil
}

// deliver performs up to maxAttempts POSTs to the downstream, sleeping an
// exponentially growing backoff between attempts. It returns the number of
// attempts made, whether delivery succeeded, and the last error (if any).
func (s *Service) deliver(url, id string, payload []byte) (attempts int, delivered bool, lastErr string) {
	for attempt := 1; attempt <= s.maxAttempts; attempt++ {
		attempts = attempt
		if err := s.deliverOnce(url, id, payload); err != nil {
			lastErr = err.Error()
			if attempt < s.maxAttempts {
				time.Sleep(s.baseBackoff << (attempt - 1))
			}
			continue
		}
		return attempts, true, ""
	}
	return attempts, false, lastErr
}

// deliverOnce issues a single POST of the raw payload to the downstream.
func (s *Service) deliverOnce(url, id string, payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Webhook-Id", id)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 300 {
		return fmt.Errorf("downstream returned status %d", resp.StatusCode)
	}
	return nil
}

// hexSig returns the lowercase hex HMAC-SHA256 of payload under secret.
func hexSig(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// secureEqual compares two strings in constant time. A length mismatch short-
// circuits (length is not secret here), but equal-length comparison never
// returns early on a byte mismatch, avoiding a timing side channel.
func secureEqual(a, b string) bool {
	ab, bb := []byte(a), []byte(b)
	if len(ab) != len(bb) {
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

// clone returns a deep-enough copy of the event for safe external use. The
// Payload slice is copied so callers cannot mutate the stored payload.
func (e *Event) clone() *Event {
	c := *e
	c.Payload = e.Payload
	c.PayloadS = string(c.Payload)
	return &c
}

// sortBySeq sorts events by ascending insertion sequence (creation order).
func sortBySeq(events []*Event) {
	// In-place insertion sort: lists are tiny, and it keeps the dependency
	// surface to the standard library's sort package minimal.
	for i := 1; i < len(events); i++ {
		for j := i; j > 0 && events[j-1].seq > events[j].seq; j-- {
			events[j-1], events[j] = events[j], events[j-1]
		}
	}
}

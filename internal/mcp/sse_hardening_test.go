package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- R1 regression: 202 must be returned before execution completes ---

func TestSSE_202ReturnedBeforeExecutionCompletes(t *testing.T) {
	sse, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	// Block execution inside handleRequest so a synchronous implementation
	// could never answer the POST in time.
	execStarted := make(chan struct{}, 16)
	release := make(chan struct{})
	sse.server.preExec = func(jsonRPCRequest) {
		execStarted <- struct{}{}
		<-release
	}

	_, reader := openSSEStream(t, ts.URL, "secret-token")
	endpoint := readEndpointEvent(t, reader)

	respCh := make(chan *http.Response, 1)
	go func() {
		respCh <- postRPC(t, ts.URL, "secret-token", endpoint, rpcRequest(1, "ping", nil))
	}()

	var resp *http.Response
	select {
	case resp = <-respCh:
	case <-time.After(2 * time.Second):
		t.Fatal("POST /messages did not return while execution was blocked; 202 is not asynchronous")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}

	// Prove the request actually reached (blocked) execution.
	select {
	case <-execStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("request never reached execution")
	}
	close(release)

	r := readRPCResponse(t, reader)
	if r.Error != nil {
		t.Fatalf("unexpected error: %+v", r.Error)
	}
}

// --- Per-connection outstanding-job cap (hard, includes queued jobs) ---

func TestSSE_PerConnectionInflightCap(t *testing.T) {
	sse, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, func(cfg *Config) {
		cfg.RateLimit = 1000 // do not interfere with the flood
	})

	release := make(chan struct{})
	sse.server.preExec = func(jsonRPCRequest) { <-release }

	_, reader := openSSEStream(t, ts.URL, "secret-token")
	endpoint := readEndpointEvent(t, reader)

	// Fill all per-connection slots with requests that cannot finish.
	for i := 1; i <= maxInflightPerConn; i++ {
		resp := postRPC(t, ts.URL, "secret-token", endpoint, rpcRequest(i, "ping", nil))
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("request %d status = %d, want 202", i, resp.StatusCode)
		}
	}

	// One more must be rejected: queued jobs count against the cap.
	extra := postRPC(t, ts.URL, "secret-token", endpoint, rpcRequest(99, "ping", nil))
	extra.Body.Close()
	if extra.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("overflow request status = %d, want 429", extra.StatusCode)
	}

	close(release)
	for i := 1; i <= maxInflightPerConn; i++ {
		readRPCResponse(t, reader)
	}
}

// --- Authentication failures are audited ---

func TestSSE_AuthFailureAudited(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.json")

	srv := newTestServer(t, func(cfg *Config) {
		cfg.AuditLogPath = auditPath
		cfg.AuditLevel = "command"
	})
	sse, err := NewSSEServer(srv, map[string]string{"secret-token": "tester"}, SSEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = sse.Shutdown(ctx)
	})
	ts := httptest.NewServer(sse.Handler())
	t.Cleanup(ts.Close)

	// Missing token.
	resp, err := http.Get(ts.URL + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want 401", resp.StatusCode)
	}
	// Invalid token.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/sse", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp2, herr := http.DefaultClient.Do(req)
	if herr != nil {
		t.Fatal(herr)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid token status = %d, want 401", resp2.StatusCode)
	}

	// The audit logger batches asynchronously (~100ms window); poll until
	// both events are flushed. Server.Close (test cleanup) owns closing it.
	deadline := time.Now().Add(3 * time.Second)
	var content string
	for {
		data, rerr := os.ReadFile(auditPath)
		if rerr == nil {
			content = string(data)
			if strings.Count(content, "mcp auth failed") >= 2 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit log missing auth failure events; got:\n%s", content)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// --- POST body read timeout ---

type dripBody struct {
	interval time.Duration
	written  int
}

func (d *dripBody) Read(p []byte) (int, error) {
	time.Sleep(d.interval)
	d.written++
	if d.written > 50 {
		// Never signal EOF/error: keep the request body open so the server
		// must hit its read timeout. The test ends long before this unblocks.
		time.Sleep(30 * time.Second)
		d.written = 0
	}
	p[0] = 'x'
	return 1, nil
}

func TestSSE_BodyReadTimeout(t *testing.T) {
	origTimeout := sseBodyReadTimeout
	sseBodyReadTimeout = 200 * time.Millisecond
	defer func() { sseBodyReadTimeout = origTimeout }()

	// Unit-test readBodyWithTimeout directly: driving it over a real HTTP
	// client makes the assertion depend on client-side body-write behavior,
	// which can mask the server-side timeout.
	r := httptest.NewRequest(http.MethodPost, "/messages", &dripBody{interval: 50 * time.Millisecond})
	rec := httptest.NewRecorder()

	start := time.Now()
	data, status, err := readBodyWithTimeout(rec, r)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if status != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", status)
	}
	if data != nil {
		t.Fatalf("expected no data, got %q", data)
	}
	if elapsed < 150*time.Millisecond {
		t.Fatalf("returned after %v; timeout not enforced", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("returned after %v; unreasonably late", elapsed)
	}
}

// --- Write deadline enforcement ---

type fakeResponseWriter struct {
	header   http.Header
	deadline time.Time
	blocking bool
}

func (f *fakeResponseWriter) Header() http.Header { return f.header }
func (f *fakeResponseWriter) WriteHeader(int)     {}
func (f *fakeResponseWriter) Write(p []byte) (int, error) {
	if f.blocking && !f.deadline.IsZero() {
		if d := time.Until(f.deadline); d > 0 {
			time.Sleep(d)
		}
		return 0, errors.New("i/o timeout: deadline exceeded")
	}
	return len(p), nil
}
func (f *fakeResponseWriter) SetWriteDeadline(t time.Time) error { f.deadline = t; return nil }

func TestWriteEventWithDeadlineBoundsStalledWriter(t *testing.T) {
	orig := sseWriteTimeout
	sseWriteTimeout = 100 * time.Millisecond
	defer func() { sseWriteTimeout = orig }()

	fw := &fakeResponseWriter{header: http.Header{}, blocking: true}
	rc := http.NewResponseController(fw)

	start := time.Now()
	err := writeEventWithDeadline(rc, fw, ": keepalive\n\n")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected write error after deadline")
	}
	if elapsed < 90*time.Millisecond {
		t.Fatalf("write returned after %v; deadline not enforced", elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("write returned after %v; unreasonably late", elapsed)
	}

	// Non-blocking writer passes through.
	fw2 := &fakeResponseWriter{header: http.Header{}}
	if err := writeEventWithDeadline(http.NewResponseController(fw2), fw2, "data\n\n"); err != nil {
		t.Fatalf("unexpected error on healthy writer: %v", err)
	}
}

// --- X-Forwarded-* trust is opt-in ---

func TestMessageEndpointURLProxyHeaders(t *testing.T) {
	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/sse", nil)
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", "evil.example.com")
		return r
	}

	// Default: headers ignored (direct clients cannot spoof their endpoint).
	untrusted, _ := NewSSEServer(newTestServer(t, nil), map[string]string{"t": "id"}, SSEOptions{})
	got := untrusted.messageEndpointURL(newReq(), "sid")
	want := "http://example.com/messages?sessionId=sid"
	if got != want {
		t.Fatalf("untrusted endpoint = %q, want %q", got, want)
	}

	// Trusted: headers honored.
	trusted, _ := NewSSEServer(newTestServer(t, nil), map[string]string{"t": "id"}, SSEOptions{TrustProxyHeaders: true})
	got = trusted.messageEndpointURL(newReq(), "sid")
	want = "https://evil.example.com/messages?sessionId=sid"
	if got != want {
		t.Fatalf("trusted endpoint = %q, want %q", got, want)
	}

	// Trusted but garbage proto value falls back to the connection scheme.
	r := httptest.NewRequest(http.MethodGet, "http://example.com/sse", nil)
	r.Header.Set("X-Forwarded-Proto", "javascript")
	got = trusted.messageEndpointURL(r, "sid")
	want = "http://example.com/messages?sessionId=sid"
	if got != want {
		t.Fatalf("invalid proto endpoint = %q, want %q", got, want)
	}
}

// --- Dispatch buffer is sized from MaxConnections ---

func TestNewSSEServer_DispatchBufferTracksMaxConnections(t *testing.T) {
	sse, err := NewSSEServer(newTestServer(t, nil), map[string]string{"t": "id"}, SSEOptions{MaxConnections: 7})
	if err != nil {
		t.Fatal(err)
	}
	if cap(sse.dispatch) != maxInflightPerConn*7 {
		t.Fatalf("dispatch buffer = %d, want %d", cap(sse.dispatch), maxInflightPerConn*7)
	}
	if sse.MaxConnections() != 7 {
		t.Fatalf("max connections = %d, want 7", sse.MaxConnections())
	}
}

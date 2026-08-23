package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Test helpers ---

func newTestServer(t *testing.T, mod func(*Config)) *Server {
	t.Helper()
	cfg := Config{
		AuditLogPath: "", // disable audit logging in tests
		AuditLevel:   "off",
	}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func newTestSSE(t *testing.T, keys map[string]string, mod func(*Config)) (*SSEServer, *httptest.Server) {
	t.Helper()
	return newTestSSEOpts(t, keys, mod, SSEOptions{})
}

func newTestSSEOpts(t *testing.T, keys map[string]string, mod func(*Config), opts SSEOptions) (*SSEServer, *httptest.Server) {
	t.Helper()
	sse, err := NewSSEServer(newTestServer(t, mod), keys, opts)
	if err != nil {
		t.Fatalf("NewSSEServer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = sse.Shutdown(ctx)
	})
	ts := httptest.NewServer(sse.Handler())
	t.Cleanup(ts.Close)
	return sse, ts
}

// sseEvent is one parsed Server-Sent Event.
type sseEvent struct {
	event string
	data  string
}

// sseReader parses an SSE stream in the background so tests can wait for
// events with a timeout instead of blocking forever on reads.
type sseReader struct {
	events chan sseEvent
	errs   chan error
}

func newSSEReader(body io.Reader) *sseReader {
	r := &sseReader{
		events: make(chan sseEvent, 16),
		errs:   make(chan error, 1),
	}
	go func() {
		br := bufio.NewReader(body)
		for {
			ev := sseEvent{event: "message"}
			hasField := false
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					r.errs <- err
					return
				}
				line = strings.TrimRight(line, "\r\n")
				if line == "" {
					break // end of event
				}
				if strings.HasPrefix(line, ":") {
					continue // comment (keepalive)
				}
				if v, ok := strings.CutPrefix(line, "event: "); ok {
					ev.event = v
					hasField = true
				} else if v, ok := strings.CutPrefix(line, "data: "); ok {
					ev.data = v
					hasField = true
				}
			}
			if hasField {
				r.events <- ev
			}
		}
	}()
	return r
}

func (r *sseReader) next(t *testing.T) sseEvent {
	t.Helper()
	select {
	case ev := <-r.events:
		return ev
	case err := <-r.errs:
		t.Fatalf("SSE stream error: %v", err)
		return sseEvent{}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for SSE event")
		return sseEvent{}
	}
}

func openSSEStream(t *testing.T, baseURL, token string) (*http.Response, *sseReader) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /sse: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /sse status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	return resp, newSSEReader(resp.Body)
}

// readEndpointEvent consumes the initial "endpoint" event and returns the
// message path announced by the server (absolute URLs are reduced to their
// path for use with postRPC).
func readEndpointEvent(t *testing.T, reader *sseReader) string {
	t.Helper()
	ev := reader.next(t)
	if ev.event != "endpoint" {
		t.Fatalf("first event = %q, want endpoint", ev.event)
	}
	idx := strings.Index(ev.data, "/messages?sessionId=")
	if idx < 0 {
		t.Fatalf("endpoint data = %q, want .../messages?sessionId=...", ev.data)
	}
	return ev.data[idx:]
}

func postRPC(t *testing.T, baseURL, token, path string, body interface{}) *http.Response {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func rpcRequest(id int, method string, params interface{}) map[string]interface{} {
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}
}

// rpcResponse is a minimal decoded JSON-RPC response for assertions.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      float64         `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func readRPCResponse(t *testing.T, reader *sseReader) rpcResponse {
	t.Helper()
	ev := reader.next(t)
	if ev.event != "message" {
		t.Fatalf("event = %q, want message", ev.event)
	}
	var resp rpcResponse
	if err := json.Unmarshal([]byte(ev.data), &resp); err != nil {
		t.Fatalf("invalid JSON-RPC response %q: %v", ev.data, err)
	}
	return resp
}

// --- Tests ---

func TestNewSSEServer_RequiresKeys(t *testing.T) {
	srv := newTestServer(t, nil)

	if _, err := NewSSEServer(srv, nil, SSEOptions{}); err == nil {
		t.Fatal("expected error when no API keys are configured")
	}
	if _, err := NewSSEServer(srv, map[string]string{"  ": "empty"}, SSEOptions{}); err == nil {
		t.Fatal("expected error when all API keys are blank")
	}
}

func TestSSE_AuthRequired(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	// No Authorization header.
	resp, err := http.Get(ts.URL + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /sse without token = %d, want 401", resp.StatusCode)
	}

	// Wrong token.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/sse", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /sse with wrong token = %d, want 401", resp.StatusCode)
	}

	// POST /messages requires auth too.
	resp = postRPC(t, ts.URL, "", "/messages?sessionId=abc", rpcRequest(1, "ping", nil))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /messages without token = %d, want 401", resp.StatusCode)
	}
}

func TestSSE_InitializeAndToolsList(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	_, reader := openSSEStream(t, ts.URL, "secret-token")
	endpoint := readEndpointEvent(t, reader)

	// initialize
	resp := postRPC(t, ts.URL, "secret-token", endpoint, rpcRequest(1, "initialize", map[string]interface{}{}))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST initialize = %d, want 202", resp.StatusCode)
	}
	initResp := readRPCResponse(t, reader)
	if initResp.Error != nil {
		t.Fatalf("initialize error: %+v", initResp.Error)
	}
	var initResult initializeResult
	if err := json.Unmarshal(initResp.Result, &initResult); err != nil {
		t.Fatalf("invalid initialize result: %v", err)
	}
	if initResult.ProtocolVersion != "2024-11-05" {
		t.Errorf("protocolVersion = %q, want 2024-11-05", initResult.ProtocolVersion)
	}
	if initResult.ServerInfo.Name != "psh-mcp" {
		t.Errorf("serverInfo.name = %q, want psh-mcp", initResult.ServerInfo.Name)
	}

	// notifications/initialized produces no response; just make sure it is accepted.
	resp = postRPC(t, ts.URL, "secret-token", endpoint, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST notifications/initialized = %d, want 202", resp.StatusCode)
	}

	// tools/list
	postRPC(t, ts.URL, "secret-token", endpoint, rpcRequest(2, "tools/list", nil))
	listResp := readRPCResponse(t, reader)
	if listResp.Error != nil {
		t.Fatalf("tools/list error: %+v", listResp.Error)
	}
	var listResult toolsListResult
	if err := json.Unmarshal(listResp.Result, &listResult); err != nil {
		t.Fatalf("invalid tools/list result: %v", err)
	}
	want := map[string]bool{"ssh_exec": false, "ssh_session_create": false, "ssh_session_exec": false, "ssh_session_close": false}
	for _, tool := range listResult.Tools {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tool %q missing from tools/list", name)
		}
	}

	// ping
	postRPC(t, ts.URL, "secret-token", endpoint, rpcRequest(3, "ping", nil))
	pingResp := readRPCResponse(t, reader)
	if pingResp.Error != nil {
		t.Fatalf("ping error: %+v", pingResp.Error)
	}
}

func TestSSE_UnknownToolRejectedViaWhitelistPath(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	_, reader := openSSEStream(t, ts.URL, "secret-token")
	endpoint := readEndpointEvent(t, reader)

	// ssh_exec against a host not in the (empty) whitelist must yield a tool
	// error, not an SSH attempt.
	postRPC(t, ts.URL, "secret-token", endpoint, rpcRequest(1, "tools/call", map[string]interface{}{
		"name":      "ssh_exec",
		"arguments": map[string]interface{}{"host": "forbidden-host", "command": "ls"},
	}))
	resp := readRPCResponse(t, reader)
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}
	var result toolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("invalid tool result: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected tool error for host outside whitelist")
	}
	if !strings.Contains(result.Content[0].Text, "whitelist") {
		t.Errorf("unexpected tool error text: %q", result.Content[0].Text)
	}
}

func TestSSE_RateLimitPerKey(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{
		"token-a": "client-a",
		"token-b": "client-b",
	}, func(cfg *Config) {
		cfg.RateLimit = 2
		cfg.RateWindow = time.Minute
	})

	_, reader := openSSEStream(t, ts.URL, "token-a")
	endpoint := readEndpointEvent(t, reader)

	call := func(id int) rpcResponse {
		postRPC(t, ts.URL, "token-a", endpoint, rpcRequest(id, "tools/call", map[string]interface{}{
			"name":      "ssh_exec",
			"arguments": map[string]interface{}{"host": "forbidden-host", "command": "ls"},
		}))
		return readRPCResponse(t, reader)
	}

	// First two calls consume the quota (rejected by the whitelist, but still counted).
	for i := 1; i <= 2; i++ {
		if resp := call(i); resp.Error != nil {
			t.Fatalf("call %d: unexpected JSON-RPC error: %+v", i, resp.Error)
		}
	}

	// Third call hits the rate limit.
	resp := call(3)
	if resp.Error == nil {
		t.Fatal("expected rate limit JSON-RPC error on third call")
	}
	if resp.Error.Code != errCodeRateLimited {
		t.Errorf("error code = %d, want %d", resp.Error.Code, errCodeRateLimited)
	}

	// A different key has its own quota.
	_, readerB := openSSEStream(t, ts.URL, "token-b")
	endpointB := readEndpointEvent(t, readerB)
	postRPC(t, ts.URL, "token-b", endpointB, rpcRequest(1, "tools/call", map[string]interface{}{
		"name":      "ssh_exec",
		"arguments": map[string]interface{}{"host": "forbidden-host", "command": "ls"},
	}))
	respB := readRPCResponse(t, readerB)
	if respB.Error != nil {
		t.Fatalf("client-b should not be rate limited: %+v", respB.Error)
	}
}

func TestSSE_MessagesUnknownSession(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	resp := postRPC(t, ts.URL, "secret-token", "/messages?sessionId=does-not-exist", rpcRequest(1, "ping", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST unknown session = %d, want 404", resp.StatusCode)
	}

	// Missing sessionId entirely.
	resp = postRPC(t, ts.URL, "secret-token", "/messages", rpcRequest(1, "ping", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST without sessionId = %d, want 404", resp.StatusCode)
	}
}

func TestSSE_SessionBoundToCreatingKey(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{
		"token-a": "client-a",
		"token-b": "client-b",
	}, nil)

	_, reader := openSSEStream(t, ts.URL, "token-a")
	endpoint := readEndpointEvent(t, reader)

	// A different valid token must not be able to drive this connection.
	resp := postRPC(t, ts.URL, "token-b", endpoint, rpcRequest(1, "ping", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST with foreign token = %d, want 404", resp.StatusCode)
	}
}

func TestSSE_BadJSONRejected(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	_, reader := openSSEStream(t, ts.URL, "secret-token")
	endpoint := readEndpointEvent(t, reader)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+endpoint, strings.NewReader("{not json"))
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST invalid JSON = %d, want 400", resp.StatusCode)
	}
}

func TestSSE_MethodNotAllowed(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/messages?sessionId=x", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /messages = %d, want 405", resp.StatusCode)
	}
}

func TestSSE_Healthz(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", resp.StatusCode)
	}
}

func TestSSE_ConnectionRegistryCleanup(t *testing.T) {
	sse, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	resp, _ := openSSEStream(t, ts.URL, "secret-token")

	// Wait for the connection to register.
	deadline := time.Now().Add(2 * time.Second)
	for sse.ConnCount() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("connection not registered, count = %d", sse.ConnCount())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Closing the stream must eventually remove the connection.
	resp.Body.Close()
	deadline = time.Now().Add(2 * time.Second)
	for sse.ConnCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("connection not cleaned up, count = %d", sse.ConnCount())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// --- Regression tests from code review ---

func TestNewSSEServer_RejectsDuplicateIdentifiers(t *testing.T) {
	srv := newTestServer(t, nil)

	_, err := NewSSEServer(srv, map[string]string{
		"token-a": "same-id",
		"token-b": "same-id",
	}, SSEOptions{})
	if err == nil {
		t.Fatal("expected error for duplicate identifiers")
	}

	_, err = NewSSEServer(srv, map[string]string{"token-a": "  "}, SSEOptions{})
	if err == nil {
		t.Fatal("expected error for blank identifier")
	}
}

func TestSSE_ConnectionLimit(t *testing.T) {
	sse, ts := newTestSSEOpts(t, map[string]string{"secret-token": "tester"}, nil, SSEOptions{MaxConnections: 1})

	// First stream takes the only slot.
	resp, _ := openSSEStream(t, ts.URL, "secret-token")
	deadline := time.Now().Add(2 * time.Second)
	for sse.ConnCount() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("connection not registered, count = %d", sse.ConnCount())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Second stream must be rejected with 429.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/sse", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second stream status = %d, want 429", resp2.StatusCode)
	}

	// Freeing the slot allows new streams again.
	resp.Body.Close()
	deadline = time.Now().Add(2 * time.Second)
	for sse.ConnCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("connection not cleaned up, count = %d", sse.ConnCount())
		}
		time.Sleep(10 * time.Millisecond)
	}
	resp3, _ := openSSEStream(t, ts.URL, "secret-token")
	_ = resp3
}

func TestSSE_OversizedBodyRejected(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	_, reader := openSSEStream(t, ts.URL, "secret-token")
	endpoint := readEndpointEvent(t, reader)

	// >1MiB body must yield 413, not 400.
	big := strings.Repeat("x", maxMessageSize+1)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+endpoint, strings.NewReader(big))
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", resp.StatusCode)
	}
}

func TestSSE_EmptyBodyRejected(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	_, reader := openSSEStream(t, ts.URL, "secret-token")
	endpoint := readEndpointEvent(t, reader)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+endpoint, strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty body status = %d, want 400", resp.StatusCode)
	}
}

func TestSSE_ConcurrentPOSTs(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	_, reader := openSSEStream(t, ts.URL, "secret-token")
	endpoint := readEndpointEvent(t, reader)

	const n = 6
	var wg sync.WaitGroup
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			resp := postRPC(t, ts.URL, "secret-token", endpoint, rpcRequest(id, "ping", nil))
			if resp.StatusCode != http.StatusAccepted {
				t.Errorf("POST %d status = %d, want 202", id, resp.StatusCode)
			}
		}(i)
	}
	wg.Wait()

	seen := make(map[int]bool)
	for i := 0; i < n; i++ {
		resp := readRPCResponse(t, reader)
		if resp.Error != nil {
			t.Fatalf("unexpected error: %+v", resp.Error)
		}
		seen[int(resp.ID)] = true
	}
	for i := 1; i <= n; i++ {
		if !seen[i] {
			t.Errorf("no response received for request id %d", i)
		}
	}
}

func TestSSE_POSTReturns202WithoutWaitingForExecution(t *testing.T) {
	// Regression (review R1): 202 must be returned before the request is
	// executed. A ping is instant, so assert the POST round-trip completes
	// promptly even while the dispatcher is the only execution path.
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	_, reader := openSSEStream(t, ts.URL, "secret-token")
	endpoint := readEndpointEvent(t, reader)

	start := time.Now()
	resp := postRPC(t, ts.URL, "secret-token", endpoint, rpcRequest(1, "ping", nil))
	elapsed := time.Since(start)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("POST took %v, expected immediate 202", elapsed)
	}
	readRPCResponse(t, reader)
}

func TestSSE_SendDropsWhenBufferFull(t *testing.T) {
	sse, _ := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	conn := &sseConn{
		id:       "unit",
		outbound: make(chan json.RawMessage, 1),
		done:     make(chan struct{}),
	}
	send := sse.makeSend(conn)

	// Fill the buffer, then one more response must tear down the connection.
	send(jsonRPCResponse{JSONRPC: "2.0", ID: 1, Result: map[string]string{}})
	select {
	case <-conn.done:
		t.Fatal("connection closed although buffer had space")
	default:
	}

	send(jsonRPCResponse{JSONRPC: "2.0", ID: 2, Result: map[string]string{}})
	select {
	case <-conn.done:
		// expected: stalled consumer triggers teardown
	case <-time.After(time.Second):
		t.Fatal("expected connection teardown when outbound buffer is full")
	}

	// Sending after teardown must not panic and must not enqueue.
	send(jsonRPCResponse{JSONRPC: "2.0", ID: 3, Result: map[string]string{}})
	if len(conn.outbound) != 1 {
		t.Fatalf("outbound len = %d, want 1", len(conn.outbound))
	}
}

func TestSSE_Shutdown(t *testing.T) {
	sse, _ := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	// Use the production Serve path so listener close is actually exercised
	// (httptest.NewServer bypasses sse.httpSrv).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- sse.Serve(ln) }()
	baseURL := "http://" + ln.Addr().String()

	resp, reader := openSSEStream(t, baseURL, "secret-token")
	_ = readEndpointEvent(t, reader)

	deadline := time.Now().Add(2 * time.Second)
	for sse.ConnCount() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("connection not registered, count = %d", sse.ConnCount())
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sse.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// Idempotent.
	if err := sse.Shutdown(ctx); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}

	// Serve must return without error once shutdown completes.
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}

	// The stream must end for connected clients.
	select {
	case <-reader.errs:
		// expected EOF/close error
	case ev := <-reader.events:
		t.Fatalf("unexpected event after shutdown: %+v", ev)
	case <-time.After(2 * time.Second):
		t.Fatal("SSE stream not closed after Shutdown")
	}
	resp.Body.Close()

	// New requests must be refused after shutdown (listener closed).
	if _, err := http.Get(baseURL + "/healthz"); err == nil {
		t.Fatal("expected connection error after shutdown")
	}
}

func TestSSE_LowercaseBearerScheme(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/sse", nil)
	req.Header.Set("Authorization", "bearer secret-token") // RFC 9110: scheme is case-insensitive
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lowercase bearer status = %d, want 200", resp.StatusCode)
	}
}

func TestSSE_EndpointEventUsesAbsoluteURL(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	_, reader := openSSEStream(t, ts.URL, "secret-token")
	ev := reader.next(t)
	if ev.event != "endpoint" {
		t.Fatalf("first event = %q, want endpoint", ev.event)
	}
	if !strings.HasPrefix(ev.data, "http://") {
		t.Fatalf("endpoint data = %q, want absolute http:// URL", ev.data)
	}
}

func TestSSE_SSEEndpointRejectsNonGET(t *testing.T) {
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	resp := postRPC(t, ts.URL, "secret-token", "/sse", rpcRequest(1, "ping", nil))
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /sse status = %d, want 405", resp.StatusCode)
	}
}

func TestSSE_ResponseWithNewlineStaysSingleFrame(t *testing.T) {
	// Frame-injection regression: content containing newlines must remain a
	// single SSE data line (JSON escaping) and stay parseable.
	_, ts := newTestSSE(t, map[string]string{"secret-token": "tester"}, nil)

	_, reader := openSSEStream(t, ts.URL, "secret-token")
	endpoint := readEndpointEvent(t, reader)

	postRPC(t, ts.URL, "secret-token", endpoint, rpcRequest(1, "tools/call", map[string]interface{}{
		"name": "bad\ntool",
	}))
	resp := readRPCResponse(t, reader)
	if resp.Error == nil {
		t.Fatal("expected error for unknown tool")
	}
	if !strings.Contains(resp.Error.Message, "bad\ntool") {
		t.Errorf("error message lost the newline content: %q", resp.Error.Message)
	}
}

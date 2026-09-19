package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

// ProtocolVersion is the admission protocol this adapter speaks. Sent on
// every request; nothing else is accepted.
const ProtocolVersion = "1"

// Header names of the admission API.
const (
	HeaderToken   = "X-Mitrity-Admission-Token" //nolint:gosec // a header name, not a credential
	HeaderVersion = "X-Mitrity-Admission-Version"
)

// MaxRequestBytes is the edge's request-body cap. A larger input is denied
// here, without sending it.
const MaxRequestBytes = 64 * 1024

const (
	maxResponseBytes = 256 * 1024
	hostName         = "mitrity-admission"
	summaryLimit     = 200
)

// UnreachableHint is appended to the reason of an adapter-side deny so the
// model can tell an outage from a policy decision.
const UnreachableHint = "This is not a policy decision — the governance edge could not be reached. " +
	"Check that the MITRITY edge is running and that MITRITY_ADMISSION_ADDR names its admission socket."

// Client talks to the loopback admission API.
//
// Safe to share across goroutines: it holds configuration only and opens one
// short-lived connection per request, reading the token file each time so an
// edge restart is picked up without the caller caring.
type Client struct {
	cfg       Config
	cfgErr    error
	network   Network
	address   string
	host      string
	port      int
	logger    *slog.Logger
	transport *http.Transport
}

// Option configures a Client.
type Option func(*Client)

// WithAddr overrides the admission address.
func WithAddr(addr string) Option { return func(c *Client) { c.cfg.Addr = addr } }

// WithTokenFile overrides the token file path.
func WithTokenFile(path string) Option { return func(c *Client) { c.cfg.TokenFile = path } }

// WithTimeout overrides the deadline for one decision.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.cfg.Timeout = d } }

// WithHoldTimeout overrides the hold budget; 0 disables the second call.
func WithHoldTimeout(d time.Duration) Option { return func(c *Client) { c.cfg.HoldTimeout = d } }

// WithLogger sets the logger. The client logs one debug line per decision
// (tool name, decision, admission id, risk, routing, latency) and never the
// tool input, the reason or the token. nil disables logging.
func WithLogger(logger *slog.Logger) Option { return func(c *Client) { c.logger = logger } }

// New builds a client from the environment (FromEnv) with the options applied
// on top. A refused address is not an error here on purpose: a hook that
// crashes at construction takes the application down; one that denies every
// call is what fail-closed means.
func New(opts ...Option) *Client {
	return NewWithConfig(FromEnv(), opts...)
}

// NewWithConfig builds a client from an explicit configuration (normalized)
// with the options applied on top.
func NewWithConfig(cfg Config, opts ...Option) *Client {
	c := &Client{cfg: cfg, logger: slog.Default()}
	for _, opt := range opts {
		opt(c)
	}
	c.cfg = c.cfg.Normalized()
	c.network, c.address = SplitAddr(c.cfg.Addr)
	if err := ValidateAddr(c.cfg.Addr); err != nil {
		c.cfgErr = err
	} else if c.network == NetworkTCP {
		// The dial target is the parsed literal host and port, never the
		// configured string, so nothing in it can name another authority.
		c.host, c.port, _ = ParseLoopbackAddr(c.address)
	}
	c.transport = &http.Transport{
		// No proxy, whatever the environment says: the edge is on this box.
		Proxy: nil,
		// No keep-alive: the edge idles connections out and a stale pooled
		// socket would surface as a spurious transport error on the next
		// decision.
		DisableKeepAlives: true,
		DialContext:       c.dial,
	}
	return c
}

// Config returns the effective configuration.
func (c *Client) Config() Config { return c.cfg }

func (c *Client) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	var d net.Dialer
	if c.network == NetworkUnix {
		return d.DialContext(ctx, "unix", c.address)
	}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(c.host, strconv.Itoa(c.port)))
}

// Admit asks for a decision. It returns an *Error on any failure; the
// deadline is the configured Timeout, bounded further by ctx.
func (c *Client) Admit(ctx context.Context, req Request) (Decision, error) {
	return c.admit(ctx, req, c.cfg.Timeout)
}

func (c *Client) admit(ctx context.Context, req Request, timeout time.Duration) (Decision, error) {
	started := time.Now()
	body, err := req.wire()
	if err != nil {
		return Decision{}, err
	}
	data, err := c.request(ctx, http.MethodPost, "/v1/admit", body, timeout, true)
	if err != nil {
		return Decision{}, err
	}
	decision, err := parseDecision(data)
	if err != nil {
		return Decision{}, err
	}
	c.log(req, decision, started)
	return decision, nil
}

// Attest reports the runtime's posture. It returns an error on failure; the
// caller logs it and never blocks on it.
func (c *Client) Attest(ctx context.Context, att Attestation) error {
	_, err := c.request(ctx, http.MethodPost, "/v1/attest", att.wire(), AttestTimeout, true)
	return err
}

// Health is GET /healthz, unauthenticated. Useful for a doctor-style check.
func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	data, err := c.request(ctx, http.MethodGet, "/healthz", nil, c.cfg.Timeout, false)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, wrapError(KindProtocol, "health response was not a JSON object", err)
	}
	return out, nil
}

// Decide is the two-phase decision: it never fails, and never fabricates an
// allow.
//
// Phase 1 asks with hold_timeout_seconds: 0 under the deadline. Only a held
// answer starts phase 2, which re-submits with the hold budget so the edge
// long-polls the approval. Anything that goes wrong on either phase is a deny
// naming what went wrong.
func (c *Client) Decide(ctx context.Context, req Request) Verdict {
	return c.decide(ctx, req, c.cfg.HoldTimeout)
}

// DecideWithHoldBudget is Decide with the hold budget capped at budget for
// this call. It can lower the configured budget, never raise it.
func (c *Client) DecideWithHoldBudget(ctx context.Context, req Request, budget time.Duration) Verdict {
	if budget < 0 {
		budget = 0
	}
	return c.decide(ctx, req, min(budget, c.cfg.HoldTimeout))
}

func (c *Client) decide(ctx context.Context, req Request, budget time.Duration) Verdict {
	first, err := c.Admit(ctx, req.withHold(0))
	if err != nil {
		return unreachableVerdict(err)
	}
	if first.Decision != Held {
		return verdictFor(first)
	}
	seconds := int(budget / time.Second)
	if seconds <= 0 {
		return verdictFor(first)
	}
	second, err := c.admit(ctx, req.withHold(seconds), time.Duration(seconds)*time.Second+HoldMargin)
	if err != nil {
		return holdFailedVerdict(first, err)
	}
	return verdictFor(second)
}

// ---------------------------------------------------------------- plumbing

func (c *Client) log(req Request, d Decision, started time.Time) {
	if c.logger == nil {
		return
	}
	// The tool input never reaches a log record, and neither does the
	// reason (it names the resolved command). What is logged is enough to
	// line a decision up against the audit trail.
	c.logger.Debug("admission decision",
		"tool", req.ToolName,
		"decision", string(d.Decision),
		"admission_id", d.AdmissionID,
		"risk", d.RiskScore,
		"routed_to", d.RoutedTo,
		"ms", time.Since(started).Milliseconds())
}

func readToken(path string) (string, error) {
	if path == "" {
		return "", newError(KindConfig, "no admission token file configured (set "+EnvTokenFile+")")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", wrapError(KindUnreachable, fmt.Sprintf(
			"admission token file %q could not be read (%v): the MITRITY edge is not running here, or is not configured to serve admission",
			path, errorText(err)), err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", newError(KindUnreachable, fmt.Sprintf("admission token file %q is empty", path))
	}
	return token, nil
}

// errorText strips the path from an *os.PathError so the message names it once.
func errorText(err error) string {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}

func encode(body any) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, wrapError(KindProtocol, "the request could not be serialized as JSON", err)
	}
	payload := bytes.TrimRight(buf.Bytes(), "\n")
	if len(payload) > MaxRequestBytes {
		return nil, newError(KindPayloadTooLarge, fmt.Sprintf(
			"the tool input is larger than MITRITY will judge (%d bytes, cap %d)", len(payload), MaxRequestBytes))
	}
	return payload, nil
}

func (c *Client) request(ctx context.Context, method, path string, body any, timeout time.Duration, auth bool) ([]byte, error) {
	if c.cfgErr != nil {
		return nil, c.cfgErr
	}
	payload, err := encode(body)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, c.contextError(err, timeout)
		}
		token := ""
		if auth {
			if token, err = readToken(c.cfg.TokenFile); err != nil {
				return nil, err
			}
		}
		status, header, data, err := c.roundTrip(ctx, method, path, payload, token)
		if err != nil {
			return nil, c.transportError(ctx, err, timeout)
		}
		if status == http.StatusUnauthorized {
			// Exactly one retry with a freshly-read token: the edge may have
			// restarted and minted a new one. A file that keeps producing
			// 401s is a broken deployment, not something to loop on.
			if attempt == 1 && ctx.Err() == nil {
				continue
			}
			return nil, newError(KindUnauthorized, "admission token rejected (401) after re-reading the token file")
		}
		return c.interpret(status, data, header)
	}
}

func (c *Client) roundTrip(ctx context.Context, method, path string, payload []byte, token string) (int, http.Header, []byte, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+hostName+path, reader)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Host = hostName
	req.Header.Set(HeaderVersion, ProtocolVersion)
	if token != "" {
		req.Header.Set(HeaderToken, token)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(payload))
	}
	client := &http.Client{
		Transport: c.transport,
		// A redirect would carry the token elsewhere; the edge never sends one.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	// A decision is a few hundred bytes; read bounded.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if len(data) > maxResponseBytes {
		return 0, nil, nil, newError(KindProtocol, "admission response exceeded the size an adapter will read")
	}
	return resp.StatusCode, resp.Header, data, nil
}

func (c *Client) contextError(err error, timeout time.Duration) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return wrapError(KindTimeout, fmt.Sprintf("admission API at %s did not answer within %d ms",
			c.cfg.Addr, timeout.Milliseconds()), err)
	}
	return wrapError(KindCanceled, "the call was canceled before the MITRITY edge answered", err)
}

func (c *Client) transportError(ctx context.Context, err error, timeout time.Duration) error {
	var adm *Error
	if errors.As(err, &adm) {
		return adm
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return c.contextError(ctxErr, timeout)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return c.contextError(context.DeadlineExceeded, timeout)
	}
	return wrapError(KindUnreachable, fmt.Sprintf("admission API at %s unreachable: %v", c.cfg.Addr, err), err)
}

// interpret turns a status, body and headers into the response body, or the
// error the contract implies.
func (c *Client) interpret(status int, body []byte, header http.Header) ([]byte, error) {
	versions, present := header[textproto.CanonicalMIMEHeaderKey(HeaderVersion)]
	if present && len(versions) > 0 && versions[0] != ProtocolVersion {
		return nil, newError(KindProtocol, fmt.Sprintf(
			"admission API at %s speaks protocol version %q; this adapter speaks %q — upgrade the edge or the adapter",
			c.cfg.Addr, versions[0], ProtocolVersion))
	}
	switch {
	case status == http.StatusNoContent:
		return nil, nil
	case status == http.StatusOK && !present:
		// Nothing authenticates the edge to the adapter; the version header
		// is the one signal that the peer is a MITRITY edge. A decision
		// without it is not obeyed.
		return nil, newError(KindProtocol, fmt.Sprintf(
			"admission API at %s answered without an %s header — not a MITRITY edge, or a protocol the adapter does not speak",
			c.cfg.Addr, HeaderVersion))
	case status == http.StatusServiceUnavailable:
		return nil, newError(KindNotReady, "the MITRITY edge is not ready to judge ("+reasonOr(body)+")")
	case status == http.StatusBadRequest:
		return nil, newError(KindProtocol, "admission API rejected the request (400): "+reasonOr(body))
	case status != http.StatusOK:
		return nil, newError(KindProtocol, fmt.Sprintf("admission API returned %d: %s", status, summarize(body)))
	}
	if !json.Valid(body) {
		return nil, newError(KindProtocol, "admission response was not valid JSON")
	}
	return body, nil
}

// summarize bounds an error body before it reaches a message the model will
// read.
func summarize(body []byte) string {
	text := strings.TrimSpace(string(body))
	text = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, text)
	if len(text) > summaryLimit {
		return text[:summaryLimit] + "…"
	}
	return text
}

// reasonOr returns the reason/error field of a JSON error body, else a
// bounded summary of it.
func reasonOr(body []byte) string {
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return summarize(body)
	}
	for _, key := range []string{"reason", "error"} {
		if value, ok := data[key].(string); ok && value != "" {
			return summarize([]byte(value))
		}
	}
	return summarize(body)
}

func verdictFor(d Decision) Verdict {
	switch d.Decision {
	case Allow:
		return Verdict{Allowed: true, Reason: d.Reason, Decision: &d, UpdatedInput: d.UpdatedInput, RoutedTo: d.RoutedTo}
	case Held:
		return Verdict{
			Allowed: false,
			Reason: "MITRITY is holding this action for human approval (approval " + approvalOr(d) +
				") and it has not been approved. Ask the operator to approve it in the MITRITY console, then try again.",
			Decision: &d,
			Held:     true,
		}
	}
	reason := d.Reason
	if reason == "" {
		reason = "MITRITY policy denied this action"
	}
	return Verdict{Allowed: false, Reason: "MITRITY denied this action: " + reason, Decision: &d}
}

func unreachableVerdict(err error) Verdict {
	return Verdict{
		Allowed: false,
		Reason:  "MITRITY could not authorize this action and blocked it: " + err.Error() + ". " + UnreachableHint,
		Err:     err,
	}
}

func holdFailedVerdict(held Decision, err error) Verdict {
	return Verdict{
		Allowed: false,
		Reason: "MITRITY held this action for human approval (approval " + approvalOr(held) +
			") and waiting on the approval failed: " + err.Error() + ". The action has not been approved.",
		Decision: &held,
		Err:      err,
		Held:     true,
	}
}

func approvalOr(d Decision) string {
	if d.ApprovalID == "" {
		return "unknown"
	}
	return d.ApprovalID
}

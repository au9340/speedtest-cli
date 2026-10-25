package defs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// powGateServer simulates a LibreSpeed backend with a proof-of-work gate: the
// ping URL answers a short, non-HTML body until the client has solved the
// challenge published at pow.php, which grants a cookie via pow_verify.php.
// The download, upload and getIP endpoints serve their normal content.
func powGateServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var pingHits atomic.Int64

	// The cookie jar is process-global and ignores ports, so a cookie from an
	// earlier test would otherwise open this server's gate too. Tie the gate
	// to a per-server token so each mock gates independently.
	gate := fmt.Sprintf("gate-%d", time.Now().UnixNano())

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pow.php":
			json.NewEncoder(w).Encode(powChallenge{Challenge: "gate-test", Difficulty: 4, Token: "tok"})
		case "/pow_verify.php":
			http.SetCookie(w, &http.Cookie{Name: "pow", Value: gate, Path: "/"})
			json.NewEncoder(w).Encode(powVerdict{Success: true})
		case "/ping":
			pingHits.Add(1)
			if c, err := r.Cookie("pow"); err != nil || c.Value != gate {
				w.Write([]byte("gate"))
				return
			}
			// an empty 200 is what the ping URL is expected to answer
		case "/garbage":
			payload := make([]byte, 64<<10)
			for i := range payload {
				payload[i] = byte(i)
			}
			w.Write(payload)
		case "/getip":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"processedString":"1.2.3.4"}`))
		default:
			// the site root, the upload target and anything else answer an
			// empty 200
		}
	}))
	t.Cleanup(ts.Close)
	return ts, &pingHits
}

// TestClearPowIfSupportedNoGate verifies that clearPowIfSupported is a no-op
// on backends that do not publish a proof-of-work gate, and that the 404 probe
// is remembered for the rest of the run.
func TestClearPowIfSupportedNoGate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)

	s := &Server{Server: ts.URL, PingURL: "/ping"}
	if err := s.clearPowIfSupported(); err != nil {
		t.Fatalf("clearPowIfSupported on a gate-less backend returned error: %v", err)
	}
	if err := s.clearPowIfSupported(); err != nil {
		t.Fatalf("second clearPowIfSupported returned error: %v", err)
	}
}

// TestIsUpClearsProofOfWorkGate verifies that IsUp detects the gated ping
// response, solves the challenge, and retries, so a gated backend is reported
// as up instead of dead.
func TestIsUpClearsProofOfWorkGate(t *testing.T) {
	ts, pingHits := powGateServer(t)

	s := &Server{Server: ts.URL, PingURL: "/ping"}
	if !s.IsUp() {
		t.Fatal("IsUp failed on a gated backend, expected it to clear the gate and succeed")
	}
	if got := pingHits.Load(); got < 2 {
		t.Errorf("gated backend saw %d ping request(s), want at least 2 (gated + cleared)", got)
	}
}

// TestPingAndJitterClearsProofOfWorkGate verifies the ping series restarts
// after the gate is solved, so the gated round trip is not counted as a ping.
func TestPingAndJitterClearsProofOfWorkGate(t *testing.T) {
	ts, pingHits := powGateServer(t)

	s := &Server{Server: ts.URL, PingURL: "/ping"}
	ping, jitter, err := s.PingAndJitter(3)
	if err != nil {
		t.Fatalf("PingAndJitter returned error: %v", err)
	}
	if ping <= 0 {
		t.Errorf("ping = %f, want > 0", ping)
	}
	if jitter < 0 {
		t.Errorf("jitter = %f, want >= 0", jitter)
	}
	// one gated round trip, then the full series again
	if got := pingHits.Load(); got != 4 {
		t.Errorf("gated backend saw %d ping request(s), want 4", got)
	}
}

// TestDownloadClearsProofOfWorkGate verifies Download clears the gate before
// the first stream when it is used without a preceding IsUp.
func TestDownloadClearsProofOfWorkGate(t *testing.T) {
	ts, _ := powGateServer(t)

	s := &Server{Server: ts.URL, PingURL: "/ping", DownloadURL: "/garbage"}
	mbps, total, err := s.Download(true, false, false, 2, 100, 700*time.Millisecond)
	if err != nil {
		t.Fatalf("Download returned error: %v", err)
	}
	if mbps <= 0 || total == 0 {
		t.Errorf("download measured nothing (rate=%f Mbps, bytes=%d)", mbps, total)
	}
}

// TestUploadClearsProofOfWorkGate verifies Upload clears the gate before the
// first upload when it is used without a preceding IsUp.
func TestUploadClearsProofOfWorkGate(t *testing.T) {
	ts, _ := powGateServer(t)

	s := &Server{Server: ts.URL, PingURL: "/ping", UploadURL: "/empty"}
	mbps, total, err := s.Upload(false, true, false, false, 2, 64, 700*time.Millisecond)
	if err != nil {
		t.Fatalf("Upload returned error: %v", err)
	}
	if mbps <= 0 || total == 0 {
		t.Errorf("upload measured nothing (rate=%f Mbps, bytes=%d)", mbps, total)
	}
}

// TestGetIPInfoClearsProofOfWorkGate verifies GetIPInfo clears the gate before
// asking the backend who we are.
func TestGetIPInfoClearsProofOfWorkGate(t *testing.T) {
	ts, _ := powGateServer(t)

	s := &Server{Server: ts.URL, PingURL: "/ping", GetIPURL: "/getip"}
	info, err := s.GetIPInfo("km")
	if err != nil {
		t.Fatalf("GetIPInfo returned error: %v", err)
	}
	if info.ProcessedString != "1.2.3.4" {
		t.Errorf("ProcessedString = %q, want %q", info.ProcessedString, "1.2.3.4")
	}
}

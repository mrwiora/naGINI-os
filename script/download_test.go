package script

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fastRetries(t *testing.T) {
	t.Helper()
	oldAttempts, oldDelay := downloadAttempts, retryDelay
	downloadAttempts, retryDelay = 3, 10*time.Millisecond
	t.Cleanup(func() { downloadAttempts, retryDelay = oldAttempts, oldDelay })
}

func tlsClient(srv *httptest.Server, allowHTTP bool) *http.Client {
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	return newHTTPClient(allowHTTP, pool)
}

func TestDownloadHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "naGINI") {
			t.Errorf("unexpected User-Agent %q", r.Header.Get("User-Agent"))
		}
		w.Write([]byte("TkdOAg==\n"))
	}))
	defer srv.Close()

	got, err := download(tlsClient(srv, false), srv.URL+"/1a2b3c4d")
	if err != nil || string(got) != "TkdOAg==\n" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDownloadRefusesHTTPSDowngradeRedirect(t *testing.T) {
	fastRetries(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("plain HTTP server must not be contacted")
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.RedirectHandler(plain.URL+"/evil", http.StatusFound))
	defer secure.Close()

	// Not even -insecure-http allows leaving HTTPS once it was used
	for _, allowHTTP := range []bool{false, true} {
		if _, err := download(tlsClient(secure, allowHTTP), secure.URL+"/1a2b3c4d"); err == nil ||
			!strings.Contains(err.Error(), "refusing redirect") {
			t.Fatalf("allowHTTP=%v: expected redirect refusal, got %v", allowHTTP, err)
		}
	}
}

func TestDownloadPlainHTTPRedirectNeedsOptIn(t *testing.T) {
	fastRetries(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	start := httptest.NewServer(http.RedirectHandler(target.URL+"/x", http.StatusFound))
	defer start.Close()

	if _, err := download(newHTTPClient(false, nil), start.URL); err == nil {
		t.Fatal("expected refusal without -insecure-http")
	}
	if got, err := download(newHTTPClient(true, nil), start.URL); err != nil || string(got) != "ok" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDownloadDoesNotRetryNotFound(t *testing.T) {
	fastRetries(t)
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if _, err := download(tlsClient(srv, false), srv.URL+"/unknown1"); err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Errorf("expected 1 request, got %d", calls)
	}
}

func TestDownloadRetriesServerErrors(t *testing.T) {
	fastRetries(t)
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			http.Error(w, "backend down", http.StatusBadGateway)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	if got, err := download(tlsClient(srv, false), srv.URL+"/1a2b3c4d"); err != nil || string(got) != "ok" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDownloadRejectsUntrustedCertificateWithoutRetry(t *testing.T) {
	fastRetries(t)
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer srv.Close()

	// System roots do not trust the test certificate
	_, err := download(newHTTPClient(false, nil), srv.URL+"/1a2b3c4d")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected certificate error, got %v", err)
	}
	if calls != 0 {
		t.Errorf("handler must not run, got %d calls", calls)
	}
}

func TestDownloadSizeLimit(t *testing.T) {
	fastRetries(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 1<<20)
		for i := 0; i <= maxScriptSize>>20; i++ {
			w.Write(chunk)
		}
	}))
	defer srv.Close()

	if _, err := download(tlsClient(srv, false), srv.URL+"/big"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("expected size error, got %v", err)
	}
}

package script

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"nagini/ui"
)

const (
	// maxScriptSize caps the download; published scripts are far smaller (naGINI-web accepts 1 MiB)
	maxScriptSize = 16 << 20
	maxRedirects  = 5
)

var (
	// UserAgent is sent with every request; main sets it to include the version
	UserAgent = "naGINI"

	// downloadAttempts and retryDelay cover the time dhcpcd and NTP need after boot
	downloadAttempts = 10
	retryDelay       = 3 * time.Second
)

// DownloadScript downloads the (encrypted) script.
//
// Only HTTPS is used unless allowHTTP is set; redirects may never downgrade from HTTPS to HTTP.
// Transient network errors are retried, certificate errors that cannot be caused by a wrong
// clock are not.
func DownloadScript(scriptURL string, allowHTTP bool) ([]byte, error) {
	fmt.Printf("%sDownloading script from %s...%s\n", ui.Yellow, scriptURL, ui.Reset)
	content, err := download(newHTTPClient(allowHTTP, nil), scriptURL)
	if err != nil {
		return nil, err
	}
	fmt.Printf("%sScript downloaded successfully (%d bytes)%s\n", ui.Green, len(content), ui.Reset)
	return content, nil
}

// redirectPolicyError is returned by the redirect check; it is a decision, never retried
type redirectPolicyError string

func (e redirectPolicyError) Error() string { return string(e) }

// newHTTPClient returns a client with TLS >= 1.2 and a redirect policy that keeps HTTPS.
// rootCAs is only set by tests; nil uses the system certificate store.
func newHTTPClient(allowHTTP bool, rootCAs *x509.CertPool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return redirectPolicyError(fmt.Sprintf("stopped after %d redirects", maxRedirects))
			}
			switch req.URL.Scheme {
			case "https":
				return nil
			case "http":
				if allowHTTP && via[0].URL.Scheme == "http" {
					return nil
				}
				return redirectPolicyError("refusing redirect to insecure URL " + req.URL.Redacted())
			default:
				return redirectPolicyError("refusing redirect to " + req.URL.Redacted())
			}
		},
	}
}

// download fetches the URL, retrying transient errors
func download(client *http.Client, scriptURL string) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= downloadAttempts; attempt++ {
		content, retry, err := downloadOnce(client, scriptURL)
		if err == nil {
			return content, nil
		}
		lastErr = err
		if !retry || attempt == downloadAttempts {
			break
		}
		fmt.Printf("%sDownload failed (%v), retrying in %s (%d/%d)...%s\n",
			ui.Yellow, err, retryDelay, attempt, downloadAttempts, ui.Reset)
		time.Sleep(retryDelay)
	}
	return nil, lastErr
}

// downloadOnce performs one request; retry reports whether the error may be transient
func downloadOnce(client *http.Client, scriptURL string) (content []byte, retry bool, err error) {
	req, err := http.NewRequest(http.MethodGet, scriptURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("invalid script URL: %v", err)
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, isTransient(err), describeTransportError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 5xx may come from a proxy while the backend restarts; 4xx (e.g. unknown ID) will not change
		return nil, resp.StatusCode >= 500, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	content, err = io.ReadAll(io.LimitReader(resp.Body, maxScriptSize+1))
	if err != nil {
		return nil, true, fmt.Errorf("failed to read script content: %v", err)
	}
	if len(content) > maxScriptSize {
		return nil, false, fmt.Errorf("script is larger than %d bytes, refusing it", maxScriptSize)
	}
	return content, false, nil
}

// isTransient reports whether a transport error may go away by waiting
// (network not up yet, DNS, timeouts, clock not yet synchronised)
func isTransient(err error) bool {
	var policy redirectPolicyError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certErr x509.CertificateInvalidError
	switch {
	case errors.As(err, &policy), errors.As(err, &unknownAuthority), errors.As(err, &hostname):
		return false
	case errors.As(err, &certErr):
		// "expired or not yet valid" can be a clock that NTP has not corrected yet
		return certErr.Reason == x509.Expired
	}
	return true
}

// describeTransportError adds a hint for certificate errors that are usually caused by the clock
func describeTransportError(err error) error {
	if certErr := (x509.CertificateInvalidError{}); errors.As(err, &certErr) && certErr.Reason == x509.Expired {
		return fmt.Errorf("failed to download script: %v (check the system clock: %s)", err, time.Now().UTC().Format(time.RFC3339))
	}
	return fmt.Errorf("failed to download script: %v", err)
}

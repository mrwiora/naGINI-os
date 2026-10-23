package config

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// SystemInfo holds detected system information
type SystemInfo struct {
	Disk         string
	Interface    string
	InterfaceMac string
}

// Config holds all configuration parameters
type Config struct {
	Disk        string
	Interface   string
	ScriptURL   string
	Passphrase  string
	ShowVersion bool

	// InsecureHTTP permits plain http:// script URLs
	InsecureHTTP bool
}

// ParseFlags parses command line arguments and returns configuration
func ParseFlags() Config {
	var config Config

	flag.StringVar(&config.Disk, "disk", "", "Target disk for installation (e.g. /dev/sda)")
	flag.StringVar(&config.Interface, "interface", "", "Network interface to use (e.g. eth0 or MAC address aa:bb:cc:dd:ee:ff)")
	flag.StringVar(&config.ScriptURL, "url", "", "Full script URL (e.g. https://script.0x7e.eu/b343cbd0); the last path segment is the script ID")
	flag.StringVar(&config.Passphrase, "passphrase", "", "Passphrase for decrypting the script (visible in the process list; prefer NAGINI_PASSPHRASE or the interactive prompt)")
	flag.BoolVar(&config.ShowVersion, "version", false, "Show version information")
	flag.BoolVar(&config.InsecureHTTP, "insecure-http", false, "Allow plain http:// script URLs (the script can be tampered with in transit)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -disk /dev/sda -interface eth0 -url https://script.0x7e.eu/1a2b3c4d  # passphrase is prompted\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -interface aa:bb:cc:dd:ee:ff -url https://script.0x7e.eu/1234affe  # Using MAC address\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  NAGINI_PASSPHRASE=\"...\" %s -url https://script.0x7e.eu/1234affe  # Non-interactive passphrase\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -url https://script.0x7e.eu/1234affe  # Interactive mode for other parameters\n", os.Args[0])
	}

	flag.Parse()

	// Remove trailing slash from script URL if present
	config.ScriptURL = strings.TrimSuffix(config.ScriptURL, "/")

	// Environment variable avoids exposing the passphrase in the process list
	if config.Passphrase == "" {
		config.Passphrase = os.Getenv("NAGINI_PASSPHRASE")
	}

	return config
}

// ValidateScriptURL checks that a script URL is well-formed and uses HTTPS.
// Plain HTTP is only accepted when allowHTTP is set.
func ValidateScriptURL(rawURL string, allowHTTP bool) error {
	if rawURL == "" {
		return fmt.Errorf("script URL cannot be empty")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid script URL: %v", err)
	}
	if parsed.Host == "" {
		return fmt.Errorf("invalid script URL: missing host")
	}

	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if allowHTTP {
			return nil
		}
		return fmt.Errorf("refusing plain http:// script URL (use https://, or -insecure-http if you accept the risk)")
	default:
		return fmt.Errorf("script URL must start with https://")
	}
}

// IsAutoMode returns true if all required parameters for automatic mode are provided
func (c Config) IsAutoMode() bool {
	return c.Disk != "" && c.Interface != "" && c.ScriptURL != ""
}

// GetScriptURL returns the full script URL
func (c Config) GetScriptURL() string {
	return c.ScriptURL
}

// GetScriptID extracts the script ID (last path segment) from the script URL
func (c Config) GetScriptID() string {
	if c.ScriptURL == "" {
		return ""
	}

	parsed, err := url.Parse(c.ScriptURL)
	if err != nil {
		// Fallback: treat the last segment after '/' as the script ID
		parts := strings.Split(c.ScriptURL, "/")
		return parts[len(parts)-1]
	}

	path := strings.TrimSuffix(parsed.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// GetBaseURL extracts the base URL (everything before the script ID) from the script URL
func (c Config) GetBaseURL() string {
	if c.ScriptURL == "" {
		return ""
	}

	scriptID := c.GetScriptID()
	if scriptID == "" {
		return c.ScriptURL
	}

	return strings.TrimSuffix(c.ScriptURL, "/"+scriptID)
}

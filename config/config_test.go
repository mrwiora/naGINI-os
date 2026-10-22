package config

import "testing"

func TestValidateScriptURL(t *testing.T) {
	cases := []struct {
		url       string
		allowHTTP bool
		ok        bool
	}{
		{"https://script.example.org/1a2b3c4d", false, true},
		{"http://script.example.org/1a2b3c4d", false, false},
		{"http://script.example.org/1a2b3c4d", true, true},
		{"ftp://script.example.org/1a2b3c4d", true, false},
		{"https:///nohost", false, false},
		{"script.example.org/1a2b3c4d", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		err := ValidateScriptURL(c.url, c.allowHTTP)
		if (err == nil) != c.ok {
			t.Errorf("ValidateScriptURL(%q, %v) error = %v, want ok=%v", c.url, c.allowHTTP, err, c.ok)
		}
	}
}

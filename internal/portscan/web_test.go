package portscan

import "testing"

func TestWebURL(t *testing.T) {
	tests := []struct {
		name    string
		result  Result
		host    string
		wantURL string
		wantOK  bool
	}{
		{"http", Result{Port: 80, Service: "http"}, "1.2.3.4", "http://1.2.3.4:80/", true},
		{"https", Result{Port: 443, Service: "https", TLS: true}, "example.com", "https://example.com:443/", true},
		{"https by name", Result{Port: 8443, Service: "https-alt"}, "10.0.0.1", "https://10.0.0.1:8443/", true},
		{"http-alt", Result{Port: 8000, Service: "http-alt"}, "10.0.0.1", "http://10.0.0.1:8000/", true},
		{"http-proxy", Result{Port: 8080, Service: "http-proxy"}, "10.0.0.1", "http://10.0.0.1:8080/", true},
		{"tls flips to https", Result{Port: 8081, Service: "http-alt", TLS: true}, "10.0.0.1", "https://10.0.0.1:8081/", true},
		{"ipv6 literal", Result{Port: 8000, Service: "http-alt"}, "2606:4700::1", "http://[2606:4700::1]:8000/", true},
		{"ssh is not web", Result{Port: 22, Service: "ssh"}, "1.2.3.4", "", false},
		{"tls-only port is not web", Result{Port: 993, Service: "imaps", TLS: true}, "1.2.3.4", "", false},
		{"unknown service", Result{Port: 12345, Service: ""}, "1.2.3.4", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url, ok := tc.result.WebURL(tc.host)
			if ok != tc.wantOK || url != tc.wantURL {
				t.Fatalf("WebURL(%s) = (%q, %v), want (%q, %v)", tc.host, url, ok, tc.wantURL, tc.wantOK)
			}
		})
	}
}

func TestWebScheme(t *testing.T) {
	tests := []struct {
		result Result
		want   string
	}{
		{Result{Service: "http"}, "http"},
		{Result{Service: "https"}, "https"},
		{Result{Service: "HTTPS"}, "https"},
		{Result{Service: "https-alt"}, "https"},
		{Result{Service: "http-alt", TLS: true}, "https"},
		{Result{Service: "smtp", TLS: true}, ""},
		{Result{Service: ""}, ""},
	}
	for _, tc := range tests {
		if got := tc.result.WebScheme(); got != tc.want {
			t.Errorf("WebScheme(%q, tls=%v) = %q, want %q", tc.result.Service, tc.result.TLS, got, tc.want)
		}
	}
}

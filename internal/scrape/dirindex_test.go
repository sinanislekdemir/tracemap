package scrape

import (
	"reflect"
	"testing"
)

func TestDirectoryURLs(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{
			"https://www.example.com/something/another/my.html",
			[]string{
				"https://www.example.com/something/another/",
				"https://www.example.com/something/",
				"https://www.example.com/",
			},
		},
		{
			"http://h/a/",
			[]string{"http://h/a/", "http://h/"},
		},
		{
			"http://h/",
			[]string{"http://h/"},
		},
		{
			"http://h/a/b?x=1#frag",
			[]string{"http://h/a/", "http://h/"},
		},
		{"not a url", nil},
		{"ftp://h/a/b", nil},
	}
	for _, tc := range cases {
		if got := directoryURLs(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("directoryURLs(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestAnalyzeIndex(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		leak    bool
		entries int
	}{
		{
			name:    "apache",
			body:    `<html><head><title>Index of /secret/</title></head><body><h1>Index of /secret/</h1><a href="../">Parent</a><a href="a.txt">a.txt</a></body></html>`,
			leak:    true,
			entries: 2,
		},
		{
			name: "nginx",
			body: `<html><head><title>Index of /x/</title></head><body><h1>Index of /x/</h1></body></html>`,
			leak: true,
		},
		{
			name: "python",
			body: `<html><head><title>Directory listing for /x/</title></head><body><h1>Directory listing for /x/</h1><a href="f">f</a></body></html>`,
			leak: true,
		},
		{
			name: "normal page mentioning index of",
			body: `<html><head><title>Welcome</title></head><body><p>The index of this site.</p></body></html>`,
			leak: false,
		},
		{
			name: "plain page",
			body: `<html><head><title>Home</title></head><body>hello</body></html>`,
			leak: false,
		},
	}
	for _, tc := range cases {
		_, entries, leak := analyzeIndex([]byte(tc.body))
		if leak != tc.leak {
			t.Errorf("%s: leak = %v, want %v", tc.name, leak, tc.leak)
		}
		if tc.entries > 0 && entries != tc.entries {
			t.Errorf("%s: entries = %d, want %d", tc.name, entries, tc.entries)
		}
	}
}

func TestSameDirectory(t *testing.T) {
	cases := []struct {
		final, probed string
		want          bool
	}{
		{"https://h/a/b/", "https://h/a/b/", true},
		{"https://h/a/b", "https://h/a/b/", true},
		{"https://h/", "https://h/a/", false},
		{"https://other/a/b/", "https://h/a/b/", false},
	}
	for _, tc := range cases {
		if got := sameDirectory(tc.final, tc.probed); got != tc.want {
			t.Errorf("sameDirectory(%q, %q) = %v, want %v", tc.final, tc.probed, got, tc.want)
		}
	}
}

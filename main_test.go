package main

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yurisenik/chaincert/internal/chain"
)

func TestIndexProbeLabel(t *testing.T) {
	const fallback = "Проверка выполняется с сервера Chaincert."
	for _, tc := range []struct {
		name, configured, want string
	}{
		{"default", "", fallback},
		{"blank", " \t\n", fallback},
		{"custom", "Подключение выполняется с сервера в России.", "Подключение выполняется с сервера в России."},
		{"escaped", `<img src=x onerror=alert(1)> & "Россия"`, `<img src=x onerror=alert(1)> & "Россия"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CHAINCERT_PROBE_LABEL", tc.configured)
			h := handler(nil, 1)
			var rootBody string
			for _, path := range []string{"/", "/index.html"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
				body := w.Body.String()
				if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
					t.Fatalf("%s: unexpected response %d, %q", path, w.Code, w.Header().Get("Content-Type"))
				}
				if !strings.Contains(body, html.EscapeString(tc.want)) || strings.Contains(body, "{{.ProbeLabel}}") {
					t.Fatalf("%s: missing escaped, server-rendered probe label", path)
				}
				if tc.name == "escaped" && strings.Contains(body, tc.configured) {
					t.Fatalf("%s: unescaped HTML in probe label", path)
				}
				if path == "/" {
					rootBody = body
				} else if body != rootBody {
					t.Fatal("index.html differs from root page")
				}
			}
		})
	}
}

func TestAPI(t *testing.T) {
	calls := 0
	h := handler(func(_ context.Context, host, cert string, root bool) (chain.Result, error) {
		calls++
		if host != "example.com" || cert != "" || !root {
			t.Fatal("incorrect arguments to checker")
		}
		return chain.Result{}, nil
	}, 1)
	for _, tc := range []struct {
		body, media string
		status      int
	}{
		{`{"host":" example.com ", "includeRoot":true}`, "application/json", 200},
		{`{"host":"example.com"}`, "text/plain", 415},
		{"", "application/json", 400},
		{`{"host":"example.com"}` + strings.Repeat(" ", 270000), "application/json", 413},
		{`{"host":"example.com"} {}`, "application/json", 400},
		{`{"certPEM":"a","host":"example.com"}`, "application/json", 400},
		{`{"unknown":""}`, "application/json", 400},
		{`{"certPEM":"-----BEGIN PRIVATE KEY-----"}`, "application/json", 400},
		{`{"certPEM":"` + strings.Repeat("0", 270000) + `"}`, "application/json", 413},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/check", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.media)
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("wanted %d got %d: %s", tc.status, w.Code, w.Body.String())
		}
	}
	if calls != 1 {
		t.Fatalf("checker called %d times", calls)
	}
}

func TestCapacity(t *testing.T) {
	h := handler(nil, 0)
	r := httptest.NewRequest("POST", "/api/check", nil)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatal("missing overload response")
	}
}

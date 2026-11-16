package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yurisenik/chaincert/internal/chain"
)

//go:embed web/*
var assets embed.FS

type checker func(context.Context, string, string, bool) (chain.Result, error)

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, code int, message string) {
	respond(w, code, map[string]string{"status": "error", "message": message})
}

func handler(check checker, capacity int) http.Handler {
	mux := http.NewServeMux()
	slots := make(chan struct{}, capacity)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /api/check", func(w http.ResponseWriter, r *http.Request) {
		mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaType != "application/json" {
			problem(w, 415, "Запрос должен быть в формате JSON.")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "5")
			problem(w, 429, "Все проверки заняты. Повторите запрос через несколько секунд.")
			return
		}
		var input struct {
			Host        string `json:"host"`
			CertPEM     string `json:"certPEM"`
			IncludeRoot bool   `json:"includeRoot"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&input)
		if err == nil {
			switch trailing := dec.Decode(new(any)); trailing {
			case nil:
				err = errors.New("unexpected trailing JSON")
			case io.EOF:
				// Exactly one JSON value.
			default:
				err = trailing
			}
		}
		if err != nil {
			var size *http.MaxBytesError
			if errors.As(err, &size) {
				problem(w, 413, "Слишком большой запрос.")
			} else {
				problem(w, 400, "Проверьте структуру JSON.")
			}
			return
		}
		host, cert := strings.TrimSpace(input.Host), strings.TrimSpace(input.CertPEM)
		if (host == "") == (cert == "") {
			problem(w, 400, "Укажите адрес сервера или сертификат PEM.")
			return
		}
		if strings.Contains(strings.ToUpper(cert), "PRIVATE KEY") {
			problem(w, 400, "Вставьте только публичные сертификаты.")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
		defer cancel()
		result, err := check(ctx, host, cert, input.IncludeRoot)
		if err != nil {
			problem(w, 422, err.Error())
			return
		}
		respond(w, 200, result)
	})
	static, err := fs.Sub(assets, "web")
	if err != nil {
		panic(err)
	}
	index := template.Must(template.ParseFS(static, "index.html"))
	probeLabel := strings.TrimSpace(os.Getenv("CHAINCERT_PROBE_LABEL"))
	if probeLabel == "" {
		probeLabel = "Проверка выполняется с сервера Chaincert."
	}
	var page bytes.Buffer
	if err := index.Execute(&page, struct{ ProbeLabel string }{probeLabel}); err != nil {
		panic(err)
	}
	serveIndex := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page.Bytes())
	}
	mux.HandleFunc("GET /{$}", serveIndex)
	mux.HandleFunc("GET /index.html", serveIndex)
	mux.Handle("GET /", http.FileServer(http.FS(static)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'")
		mux.ServeHTTP(w, r)
	})
}

func main() {
	srv := &http.Server{
		Addr: ":8080", Handler: handler(chain.Check, 12),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 25 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	log.Fatal(srv.ListenAndServe())
}

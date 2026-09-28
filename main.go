package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Dusha-Su/aws-waf-mobile/solver"
)

func main() {
	proxy := flag.String("proxy", "", "http://user:pass@host:port")
	n := flag.Int("n", 1, "tokens to mint")
	direct := flag.Bool("direct", false, "mint without a proxy (leaks your IP)")
	endpoint := flag.String("endpoint", solver.DefaultEndpoint, "WAF SDK host/path")
	domain := flag.String("domain", solver.DefaultDomain, "verify domain field")
	app := flag.String("app", solver.DefaultAppID, "ApplicationID signal")
	listen := flag.String("listen", "", "if set (e.g. :8192), serve POST /solve")
	flag.Parse()

	if *listen != "" {
		http.HandleFunc("/solve", handleSolve)
		http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})
		log.Printf("listening on %s  POST /solve", *listen)
		log.Fatal(http.ListenAndServe(*listen, nil))
	}

	opt := solver.Options{
		Proxy:    strings.TrimSpace(*proxy),
		Direct:   *direct,
		Endpoint: *endpoint,
		Domain:   *domain,
		AppID:    *app,
	}
	if opt.Proxy == "" && !opt.Direct {
		fmt.Fprintln(os.Stderr, "usage: aws-waf-mobile -proxy http://user:pass@host:port")
		os.Exit(2)
	}

	ok := 0
	for i := 0; i < *n; i++ {
		tok, err := solver.Mint(opt)
		if err != nil {
			fmt.Printf("[%d] fail %v\n", i, err)
			continue
		}
		ok++
		fmt.Println(tok)
	}
	if ok == 0 {
		os.Exit(1)
	}
}

type solveReq struct {
	Proxy    string `json:"proxy"`
	Direct   bool   `json:"direct"`
	Endpoint string `json:"endpoint"`
	Domain   string `json:"domain"`
	App      string `json:"app"`
}

type solveResp struct {
	Success  bool   `json:"success"`
	Token    string `json:"token,omitempty"`
	TokenLen int    `json:"token_len,omitempty"`
	Error    string `json:"error,omitempty"`
}

func handleSolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req solveReq
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, solveResp{Error: "bad json"})
			return
		}
	}
	tok, err := solver.Mint(solver.Options{
		Proxy:    req.Proxy,
		Direct:   req.Direct,
		Endpoint: req.Endpoint,
		Domain:   req.Domain,
		AppID:    req.App,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, solveResp{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, solveResp{Success: true, Token: tok, TokenLen: len(tok)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

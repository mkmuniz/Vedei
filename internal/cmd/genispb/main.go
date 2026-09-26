// Command genispb rebuilds the embedded ISPB registry from the upstream
// BancosBrasileiros dataset.
//
// Only three fields survive: the ISPB itself, a short name for reporting,
// and whether the institution participates in Pix. Everything else in the
// source dataset is irrelevant to validation and would only inflate the
// binary.
//
// Run with: make update-ispb
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const sourceURL = "https://raw.githubusercontent.com/guibranco/BancosBrasileiros/main/data/bancos.json"

const outPath = "detect/br/assets/ispb.tsv.gz"

type bank struct {
	ISPB      string `json:"ISPB"`
	ShortName string `json:"ShortName"`
	PixType   string `json:"PixType"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "genispb:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching dataset: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching dataset: status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("reading dataset: %w", err)
	}
	// The upstream file is served with a UTF-8 BOM, which json.Unmarshal rejects.
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})

	var banks []bank
	if err := json.Unmarshal(raw, &banks); err != nil {
		return fmt.Errorf("parsing dataset: %w", err)
	}
	if len(banks) < 400 {
		return fmt.Errorf("dataset has only %d records; refusing to shrink the registry", len(banks))
	}

	rows := make([]string, 0, len(banks))
	seen := make(map[string]bool, len(banks))
	for _, b := range banks {
		if len(b.ISPB) != 8 || seen[b.ISPB] {
			continue
		}
		seen[b.ISPB] = true
		name := strings.ReplaceAll(strings.TrimSpace(b.ShortName), "\t", " ")
		rows = append(rows, b.ISPB+"\t"+name+"\t"+b.PixType)
	}
	sort.Strings(rows)

	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := zw.Write([]byte(strings.Join(rows, "\n") + "\n")); err != nil {
		return fmt.Errorf("compressing: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("closing gzip: %w", err)
	}

	if err := os.WriteFile(outPath, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", outPath, err)
	}

	fmt.Printf("wrote %s: %d institutions, %d bytes\n", outPath, len(rows), buf.Len())
	return nil
}

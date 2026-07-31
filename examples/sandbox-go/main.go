package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	url := "https://example.com"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}

	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GET %s failed: %v\n", url, err)
		os.Exit(1)
	}
	defer response.Body.Close()

	bytes, err := io.Copy(io.Discard, response.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s failed: %v\n", url, err)
		os.Exit(1)
	}
	tlsIssuer := ""
	if response.TLS != nil && len(response.TLS.PeerCertificates) != 0 {
		tlsIssuer = response.TLS.PeerCertificates[0].Issuer.CommonName
	}

	fmt.Printf(
		"url=%s status=%s bytes=%d tls_issuer=%q ssl_cert_file=%s\n",
		url,
		response.Status,
		bytes,
		tlsIssuer,
		os.Getenv("SSL_CERT_FILE"),
	)
}

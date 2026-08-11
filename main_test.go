package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Port != 80 {
		t.Errorf("expected Port 80, got %d", config.Port)
	}
	if config.SSLPort != 443 {
		t.Errorf("expected SSLPort 443, got %d", config.SSLPort)
	}
	if config.Dir != "." {
		t.Errorf("expected Dir '.', got %q", config.Dir)
	}
}

func TestConfigParseFlags(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		check func(*Config) error
	}{
		{
			name: "custom port",
			args: []string{"-port", "8080"},
			check: func(c *Config) error {
				if c.Port != 8080 {
					return fmt.Errorf("Port = %d, want 8080", c.Port)
				}
				return nil
			},
		},
		{
			name: "disable ssl",
			args: []string{"-sslport", "0"},
			check: func(c *Config) error {
				if c.SSLPort != 0 {
					return fmt.Errorf("SSLPort = %d, want 0", c.SSLPort)
				}
				return nil
			},
		},
		{
			name: "savekeys",
			args: []string{"-savekeys"},
			check: func(c *Config) error {
				if !c.SaveKeys {
					return fmt.Errorf("SaveKeys = false, want true")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			if err := config.ParseFlags(tt.args); err != nil {
				t.Fatalf("ParseFlags() error = %v", err)
			}
			if err := tt.check(config); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{name: "negative HTTP port", config: Config{Port: -1}},
		{name: "HTTP port too large", config: Config{Port: 65536}},
		{name: "negative SSL port", config: Config{SSLPort: -1}},
		{name: "SSL port too large", config: Config{SSLPort: 65536}},
		{name: "no servers enabled", config: Config{NoHTTP: true}},
		{name: "missing certificate path", config: Config{SSLPort: 443, SSLKey: "key"}},
		{name: "missing key path", config: Config{SSLPort: 443, SSLCert: "cert"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.Validate(); err == nil {
				t.Fatal("Validate() returned nil")
			}
		})
	}

	if err := (*Config)(nil).Validate(); err == nil {
		t.Fatal("nil config validation returned nil")
	}
}

func TestServerRun(t *testing.T) {
	tmpDir := t.TempDir()
	outsideDir := t.TempDir()
	testContent := "Hello, Gomoose!"
	if err := os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("private"), 0600); err != nil {
		t.Fatalf("Failed to write outside file: %v", err)
	}
	if err := os.Symlink(filepath.Join(outsideDir, "secret.txt"), filepath.Join(tmpDir, "outside-link")); err != nil {
		t.Fatalf("Failed to create outside symlink: %v", err)
	}
	if err := os.Symlink("index.html", filepath.Join(tmpDir, "inside-link")); err != nil {
		t.Fatalf("Failed to create inside symlink: %v", err)
	}

	config := &Config{
		Host:    "127.0.0.1",
		Port:    0,
		SSLPort: 0,
		Dir:     tmpDir,
	}
	_, address := startTestServer(t, config, false)

	resp := getWithRetry(t, http.DefaultClient, "http://"+address+"/index.html")
	defer closeResource(t, resp.Body, "HTTP response body")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	if string(body) != testContent {
		t.Errorf("Expected body %q, got %q", testContent, string(body))
	}

	resp = getWithRetry(t, http.DefaultClient, "http://"+address+"/inside-link")
	defer closeResource(t, resp.Body, "HTTP symlink response body")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected inside symlink status 200, got %d with body %q", resp.StatusCode, body)
	}

	resp = getWithRetry(t, http.DefaultClient, "http://"+address+"/outside-link")
	closeResource(t, resp.Body, "HTTP response body")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected outside symlink status 404, got %d", resp.StatusCode)
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert() error = %v", err)
	}

	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Error("generated certificate or key is empty")
	}

	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("Failed to parse generated certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("generated certificate is not PEM encoded")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("generated certificate does not cover 127.0.0.1: %v", err)
	}
}

func TestServerHTTPSWithGeneratedCert(t *testing.T) {
	tmpDir := t.TempDir()
	testContent := "Hello, HTTPS!"
	if err := os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	config := &Config{
		SSLHost: "127.0.0.1",
		SSLPort: freePort(t),
		NoHTTP:  true,
		Dir:     tmpDir,
		SSLCert: filepath.Join(tmpDir, "nonexistent.crt"),
		SSLKey:  filepath.Join(tmpDir, "nonexistent.key"),
	}
	_, address := startTestServer(t, config, true)

	client := &http.Client{
		Transport: &http.Transport{
			// The server intentionally uses a generated self-signed certificate.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only client
		},
	}
	resp := getWithRetry(t, client, "https://"+address+"/index.html")
	defer closeResource(t, resp.Body, "HTTPS response body")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestServerBlocksPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate certs: %v", err)
	}
	certFile := filepath.Join(tmpDir, "cert.crt")
	keyFile := filepath.Join(tmpDir, "cert.key")
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "regular.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("Failed to write regular file: %v", err)
	}
	if err := os.Symlink(keyFile, filepath.Join(tmpDir, "key-alias")); err != nil {
		t.Fatalf("Failed to create key symlink: %v", err)
	}

	config := &Config{
		Host:    "127.0.0.1",
		Port:    0,
		SSLPort: freePort(t),
		Dir:     tmpDir,
		SSLCert: certFile,
		SSLKey:  keyFile,
	}
	_, address := startTestServer(t, config, false)

	resp := getWithRetry(t, http.DefaultClient, "http://"+address+"/regular.txt")
	closeResource(t, resp.Body, "HTTP response body")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected regular file status 200, got %d", resp.StatusCode)
	}

	for _, file := range []string{"cert.key", "key-alias"} {
		resp = getWithRetry(t, http.DefaultClient, "http://"+address+"/"+file)
		closeResource(t, resp.Body, "HTTP response body")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected %s to return 404, got %d", file, resp.StatusCode)
		}
	}
}

func TestLoadTLSConfigRejectsDirectoryPaths(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.crt")
	keyPath := filepath.Join(tmpDir, "cert.key")
	if err := os.Mkdir(certPath, 0700); err != nil {
		t.Fatalf("Failed to create certificate directory: %v", err)
	}
	if err := os.Mkdir(keyPath, 0700); err != nil {
		t.Fatalf("Failed to create key directory: %v", err)
	}

	server := &Server{config: &Config{SSLCert: certPath, SSLKey: keyPath}}
	if _, err := server.loadTLSConfig(); err == nil {
		t.Fatal("loadTLSConfig() accepted directory paths")
	}
}

func TestWriteExclusiveFileDoesNotFollowSymlinks(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target")
	path := filepath.Join(tmpDir, "output")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Failed to create output symlink: %v", err)
	}

	if err := writeExclusiveFile(path, []byte("replacement"), 0600); err == nil {
		t.Fatal("writeExclusiveFile() followed an existing symlink")
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("Failed to read target file: %v", err)
	}
	if string(contents) != "original" {
		t.Fatalf("target file changed to %q", contents)
	}
}

func startTestServer(t *testing.T, config *Config, secure bool) (*Server, string) {
	t.Helper()
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var runErr error
	go func() {
		runErr = server.Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if address := server.serverAddress(secure); address != "" {
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
					if runErr != nil {
						t.Errorf("server shutdown error: %v", runErr)
					}
				case <-time.After(2 * time.Second):
					server.Shutdown()
					t.Error("server did not shut down")
				}
			})
			return server, address
		}
		select {
		case <-done:
			t.Fatalf("server stopped during startup: %v", runErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start listening")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func getWithRetry(t *testing.T, client *http.Client, target string) *http.Response {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(target)
		if err == nil {
			return resp
		}
		lastErr = err
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("GET %s failed: %v", target, lastErr)
	return nil
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a test port: %v", err)
	}
	defer closeResource(t, listener, "test listener")
	return listener.Addr().(*net.TCPAddr).Port
}

func closeResource(t *testing.T, resource io.Closer, name string) {
	t.Helper()
	if err := resource.Close(); err != nil {
		t.Errorf("failed to close %s: %v", name, err)
	}
}

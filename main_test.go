package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
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
		name     string
		args     []string
		check    func(*Config) error
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

func TestServerRun(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gomoose-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testContent := "Hello, Gomoose!"
	if err := os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	port := 18080
	config := &Config{
		Host:    "127.0.0.1",
		Port:    port,
		SSLPort: 0,
		Dir:     tmpDir,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/index.html", port))
	if err != nil {
		t.Fatalf("HTTP GET error: %v", err)
	}
	defer resp.Body.Close()

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
}

func TestServerHTTPSWithGeneratedCert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gomoose-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testContent := "Hello, HTTPS!"
	if err := os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	sslPort := 18443
	config := &Config{
		Host:    "127.0.0.1",
		SSLHost: "127.0.0.1",
		SSLPort: sslPort,
		NoHTTP:  true,
		Dir:     tmpDir,
		SSLCert: "nonexistent.crt",
		SSLKey:  "nonexistent.key",
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Run(ctx) }()
	time.Sleep(200 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/index.html", sslPort))
	if err != nil {
		t.Fatalf("HTTPS GET error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestServerBlocksPrivateKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gomoose-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

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

	port := 18084
	config := &Config{
		Host:    "127.0.0.1",
		Port:    port,
		SSLPort: 18444,
		Dir:     tmpDir,
		SSLCert: certFile,
		SSLKey:  keyFile,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Run(ctx) }()
	time.Sleep(200 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/regular.txt", port))
	if err != nil {
		t.Fatalf("HTTP GET error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected regular file status 200, got %d", resp.StatusCode)
	}

	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/cert.key", port))
	if err != nil {
		t.Fatalf("HTTP GET error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected key file to return 404, got %d", resp.StatusCode)
	}
}

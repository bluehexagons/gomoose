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

	if config.Host != "" {
		t.Errorf("expected empty Host, got %q", config.Host)
	}
	if config.Port != 80 {
		t.Errorf("expected Port 80, got %d", config.Port)
	}
	if config.SSLPort != 443 {
		t.Errorf("expected SSLPort 443, got %d", config.SSLPort)
	}
	if config.NoHTTP != false {
		t.Errorf("expected NoHTTP false, got %v", config.NoHTTP)
	}
	if config.UseSSL != true {
		t.Errorf("expected UseSSL true, got %v", config.UseSSL)
	}
	if config.NoSSL != false {
		t.Errorf("expected NoSSL false, got %v", config.NoSSL)
	}
	if config.Dir != "." {
		t.Errorf("expected Dir '.', got %q", config.Dir)
	}
	if config.SSLCert != "cert.crt" {
		t.Errorf("expected SSLCert 'cert.crt', got %q", config.SSLCert)
	}
	if config.SSLKey != "cert.key" {
		t.Errorf("expected SSLKey 'cert.key', got %q", config.SSLKey)
	}
	if config.SaveKeys != false {
		t.Errorf("expected SaveKeys false, got %v", config.SaveKeys)
	}
}

func TestConfigParseFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected Config
	}{
		{
			name: "default values",
			args: []string{},
			expected: Config{
				Host:     "",
				SSLHost:  "",
				Port:     80,
				SSLPort:  443,
				NoHTTP:   false,
				UseSSL:   true,
				NoSSL:    false,
				Dir:      ".",
				SSLCert:  "cert.crt",
				SSLKey:   "cert.key",
				SaveKeys: false,
			},
		},
		{
			name: "custom port",
			args: []string{"-port", "8080"},
			expected: Config{
				Host:     "",
				SSLHost:  "",
				Port:     8080,
				SSLPort:  443,
				NoHTTP:   false,
				UseSSL:   true,
				NoSSL:    false,
				Dir:      ".",
				SSLCert:  "cert.crt",
				SSLKey:   "cert.key",
				SaveKeys: false,
			},
		},
		{
			name: "custom dir",
			args: []string{"-dir", "/tmp/www"},
			expected: Config{
				Host:     "",
				SSLHost:  "",
				Port:     80,
				SSLPort:  443,
				NoHTTP:   false,
				UseSSL:   true,
				NoSSL:    false,
				Dir:      "/tmp/www",
				SSLCert:  "cert.crt",
				SSLKey:   "cert.key",
				SaveKeys: false,
			},
		},
		{
			name: "ssl disabled with nossl",
			args: []string{"-nossl"},
			expected: Config{
				Host:     "",
				SSLHost:  "",
				Port:     80,
				SSLPort:  443,
				NoHTTP:   false,
				UseSSL:   true,
				NoSSL:    true,
				Dir:      ".",
				SSLCert:  "cert.crt",
				SSLKey:   "cert.key",
				SaveKeys: false,
			},
		},
		{
			name: "ssl with custom port",
			args: []string{"-sslport", "8443"},
			expected: Config{
				Host:     "",
				SSLHost:  "",
				Port:     80,
				SSLPort:  8443,
				NoHTTP:   false,
				UseSSL:   true,
				NoSSL:    false,
				Dir:      ".",
				SSLCert:  "cert.crt",
				SSLKey:   "cert.key",
				SaveKeys: false,
			},
		},
		{
			name: "nohttp flag",
			args: []string{"-nohttp"},
			expected: Config{
				Host:     "",
				SSLHost:  "",
				Port:     80,
				SSLPort:  443,
				NoHTTP:   true,
				UseSSL:   true,
				NoSSL:    false,
				Dir:      ".",
				SSLCert:  "cert.crt",
				SSLKey:   "cert.key",
				SaveKeys: false,
			},
		},
		{
			name: "custom host",
			args: []string{"-host", "127.0.0.1"},
			expected: Config{
				Host:     "127.0.0.1",
				SSLHost:  "",
				Port:     80,
				SSLPort:  443,
				NoHTTP:   false,
				UseSSL:   true,
				NoSSL:    false,
				Dir:      ".",
				SSLCert:  "cert.crt",
				SSLKey:   "cert.key",
				SaveKeys: false,
			},
		},
		{
			name: "savekeys flag",
			args: []string{"-savekeys"},
			expected: Config{
				Host:     "",
				SSLHost:  "",
				Port:     80,
				SSLPort:  443,
				NoHTTP:   false,
				UseSSL:   true,
				NoSSL:    false,
				Dir:      ".",
				SSLCert:  "cert.crt",
				SSLKey:   "cert.key",
				SaveKeys: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			err := config.ParseFlags(tt.args)
			if err != nil {
				t.Fatalf("ParseFlags() error = %v", err)
			}

			if config.Host != tt.expected.Host {
				t.Errorf("Host = %q, want %q", config.Host, tt.expected.Host)
			}
			if config.SSLHost != tt.expected.SSLHost {
				t.Errorf("SSLHost = %q, want %q", config.SSLHost, tt.expected.SSLHost)
			}
			if config.Port != tt.expected.Port {
				t.Errorf("Port = %d, want %d", config.Port, tt.expected.Port)
			}
			if config.SSLPort != tt.expected.SSLPort {
				t.Errorf("SSLPort = %d, want %d", config.SSLPort, tt.expected.SSLPort)
			}
			if config.NoHTTP != tt.expected.NoHTTP {
				t.Errorf("NoHTTP = %v, want %v", config.NoHTTP, tt.expected.NoHTTP)
			}
			if config.UseSSL != tt.expected.UseSSL {
				t.Errorf("UseSSL = %v, want %v", config.UseSSL, tt.expected.UseSSL)
			}
			if config.Dir != tt.expected.Dir {
				t.Errorf("Dir = %q, want %q", config.Dir, tt.expected.Dir)
			}
			if config.SSLCert != tt.expected.SSLCert {
				t.Errorf("SSLCert = %q, want %q", config.SSLCert, tt.expected.SSLCert)
			}
			if config.SSLKey != tt.expected.SSLKey {
				t.Errorf("SSLKey = %q, want %q", config.SSLKey, tt.expected.SSLKey)
			}
			if config.NoSSL != tt.expected.NoSSL {
				t.Errorf("NoSSL = %v, want %v", config.NoSSL, tt.expected.NoSSL)
			}
			if config.SaveKeys != tt.expected.SaveKeys {
				t.Errorf("SaveKeys = %v, want %v", config.SaveKeys, tt.expected.SaveKeys)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name            string
		config          Config
		expectedSSLPort int
		expectedUseSSL  bool
	}{
		{
			name: "nossl flag disables ssl",
			config: Config{
				UseSSL:  true,
				NoSSL:   true,
				SSLPort: 443,
			},
			expectedSSLPort: 0,
			expectedUseSSL:  false,
		},
		{
			name: "explicit ssl port enables ssl",
			config: Config{
				UseSSL:  false,
				NoSSL:   false,
				SSLPort: 8443,
			},
			expectedSSLPort: 8443,
			expectedUseSSL:  true,
		},
		{
			name: "no ssl when port is 0 and nossl set",
			config: Config{
				UseSSL:  true,
				NoSSL:   true,
				SSLPort: 0,
			},
			expectedSSLPort: 0,
			expectedUseSSL:  false,
		},
		{
			name: "default ssl enabled with port 443",
			config: Config{
				UseSSL:  true,
				NoSSL:   false,
				SSLPort: 443,
			},
			expectedSSLPort: 443,
			expectedUseSSL:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.config
			err := config.Validate()
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}

			if config.SSLPort != tt.expectedSSLPort {
				t.Errorf("SSLPort = %d, want %d", config.SSLPort, tt.expectedSSLPort)
			}
			if config.UseSSL != tt.expectedUseSSL {
				t.Errorf("UseSSL = %v, want %v", config.UseSSL, tt.expectedUseSSL)
			}
		})
	}
}

func TestNewServer(t *testing.T) {
	config := DefaultConfig()
	config.Port = 8080

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	if server == nil {
		t.Fatal("NewServer() returned nil")
	}
	if server.config != config {
		t.Error("NewServer() config not set correctly")
	}
}

func TestServerRun(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gomoose-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testContent := "Hello, Gomoose!"
	testFile := filepath.Join(tmpDir, "index.html")
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	port := 18080
	config := &Config{
		Host:   "127.0.0.1",
		Port:   port,
		NoHTTP: false,
		UseSSL: false,
		Dir:    tmpDir,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/index.html", port))
	if err != nil {
		cancel()
		t.Fatalf("HTTP GET error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body) != testContent {
		t.Errorf("Expected body %q, got %q", testContent, string(body))
	}

	cancel()

	select {
	case err := <-serverDone:
		if err != nil {
			t.Errorf("Server.Run() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Server did not shut down in time")
	}
}

func TestServerServesDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gomoose-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	files := map[string]string{
		"index.html":        "<html>Hello</html>",
		"test.txt":          "Test content",
		"subdir/nested.txt": "Nested content",
	}

	for path, content := range files {
		fullPath := filepath.Join(tmpDir, path)
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write %s: %v", path, err)
		}
	}

	port := 18081
	config := &Config{
		Host:   "127.0.0.1",
		Port:   port,
		NoHTTP: false,
		UseSSL: false,
		Dir:    tmpDir,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	for path, expectedContent := range files {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/%s", port, path))
			if err != nil {
				t.Fatalf("HTTP GET error: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}

			if string(body) != expectedContent {
				t.Errorf("Expected body %q, got %q", expectedContent, string(body))
			}
		})
	}

	cancel()
}

func TestServer404(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gomoose-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	port := 18082
	config := &Config{
		Host:   "127.0.0.1",
		Port:   port,
		NoHTTP: false,
		UseSSL: false,
		Dir:    tmpDir,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/nonexistent.txt", port))
	if err != nil {
		t.Fatalf("HTTP GET error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}

	cancel()
}

func TestGenerateSelfSignedCert(t *testing.T) {
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert() error = %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("generated certificate is empty")
	}
	if len(keyPEM) == 0 {
		t.Error("generated key is empty")
	}

	// Verify the certificate and key can be parsed
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse generated certificate: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Error("parsed certificate has no data")
	}
}

func TestServerHTTPSWithGeneratedCert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gomoose-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testContent := "Hello, HTTPS!"
	testFile := filepath.Join(tmpDir, "index.html")
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	sslPort := 18443
	config := &Config{
		Host:    "127.0.0.1",
		Port:    18083,
		SSLHost: "127.0.0.1",
		SSLPort: sslPort,
		NoHTTP:  true,
		UseSSL:  true,
		NoSSL:   false,
		Dir:     tmpDir,
		SSLCert: "nonexistent.crt", // Force generation
		SSLKey:  "nonexistent.key",
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// Create HTTP client that skips certificate verification
	// InsecureSkipVerify is intentionally used here to test self-signed certificates
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/index.html", sslPort))
	if err != nil {
		cancel()
		t.Fatalf("HTTPS GET error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body) != testContent {
		t.Errorf("Expected body %q, got %q", testContent, string(body))
	}

	cancel()

	select {
	case err := <-serverDone:
		if err != nil {
			t.Errorf("Server.Run() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Server did not shut down in time")
	}
}

func TestServerBlocksPrivateKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gomoose-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test key file in the served directory
	testKeyContent := "FAKE PRIVATE KEY CONTENT"
	keyFile := filepath.Join(tmpDir, "cert.key")
	if err := os.WriteFile(keyFile, []byte(testKeyContent), 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create a regular file too
	regularContent := "Regular content"
	regularFile := filepath.Join(tmpDir, "regular.txt")
	if err := os.WriteFile(regularFile, []byte(regularContent), 0644); err != nil {
		t.Fatalf("Failed to write regular file: %v", err)
	}

	// Generate real certs for the SSL server
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate certs: %v", err)
	}

	certFile := filepath.Join(tmpDir, "cert.crt")
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	port := 18084
	sslPort := 18444
	config := &Config{
		Host:    "127.0.0.1",
		Port:    port,
		SSLHost: "127.0.0.1",
		SSLPort: sslPort,
		NoHTTP:  false,
		UseSSL:  true,
		NoSSL:   false,
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

	go func() {
		_ = server.Run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// Test that regular file is accessible via HTTP
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/regular.txt", port))
	if err != nil {
		t.Fatalf("HTTP GET error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected regular file status 200, got %d", resp.StatusCode)
	}

	// Test that key file is blocked via HTTP
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/cert.key", port))
	if err != nil {
		t.Fatalf("HTTP GET error for key: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected key file to return 404, got %d", resp.StatusCode)
	}

	cancel()
}

func TestServerSaveKeys(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gomoose-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "generated.crt")
	keyPath := filepath.Join(tmpDir, "generated.key")

	sslPort := 18445
	config := &Config{
		Host:     "127.0.0.1",
		Port:     18085,
		SSLHost:  "127.0.0.1",
		SSLPort:  sslPort,
		NoHTTP:   true,
		UseSSL:   true,
		NoSSL:    false,
		Dir:      tmpDir,
		SSLCert:  certPath,
		SSLKey:   keyPath,
		SaveKeys: true,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// Verify cert and key files were created
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("Certificate file was not saved")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Key file was not saved")
	}

	cancel()
}

func TestFileExists(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gomoose-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	if !fileExists(testFile) {
		t.Error("fileExists() returned false for existing file")
	}

	if fileExists(filepath.Join(tmpDir, "nonexistent.txt")) {
		t.Error("fileExists() returned true for non-existing file")
	}

	// Test that directory is not considered a file
	if fileExists(tmpDir) {
		t.Error("fileExists() returned true for directory")
	}
}

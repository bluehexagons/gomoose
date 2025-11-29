package main

import (
	"context"
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
	if config.SSLPort != 0 {
		t.Errorf("expected SSLPort 0, got %d", config.SSLPort)
	}
	if config.NoHTTP != false {
		t.Errorf("expected NoHTTP false, got %v", config.NoHTTP)
	}
	if config.UseSSL != false {
		t.Errorf("expected UseSSL false, got %v", config.UseSSL)
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
				Host:    "",
				SSLHost: "",
				Port:    80,
				SSLPort: 0,
				NoHTTP:  false,
				UseSSL:  false,
				Dir:     ".",
				SSLCert: "cert.crt",
				SSLKey:  "cert.key",
			},
		},
		{
			name: "custom port",
			args: []string{"-port", "8080"},
			expected: Config{
				Host:    "",
				SSLHost: "",
				Port:    8080,
				SSLPort: 0,
				NoHTTP:  false,
				UseSSL:  false,
				Dir:     ".",
				SSLCert: "cert.crt",
				SSLKey:  "cert.key",
			},
		},
		{
			name: "custom dir",
			args: []string{"-dir", "/tmp/www"},
			expected: Config{
				Host:    "",
				SSLHost: "",
				Port:    80,
				SSLPort: 0,
				NoHTTP:  false,
				UseSSL:  false,
				Dir:     "/tmp/www",
				SSLCert: "cert.crt",
				SSLKey:  "cert.key",
			},
		},
		{
			name: "ssl enabled",
			args: []string{"-ssl"},
			expected: Config{
				Host:    "",
				SSLHost: "",
				Port:    80,
				SSLPort: 0,
				NoHTTP:  false,
				UseSSL:  true,
				Dir:     ".",
				SSLCert: "cert.crt",
				SSLKey:  "cert.key",
			},
		},
		{
			name: "ssl with custom port",
			args: []string{"-ssl", "-sslport", "8443"},
			expected: Config{
				Host:    "",
				SSLHost: "",
				Port:    80,
				SSLPort: 8443,
				NoHTTP:  false,
				UseSSL:  true,
				Dir:     ".",
				SSLCert: "cert.crt",
				SSLKey:  "cert.key",
			},
		},
		{
			name: "nohttp flag",
			args: []string{"-nohttp"},
			expected: Config{
				Host:    "",
				SSLHost: "",
				Port:    80,
				SSLPort: 0,
				NoHTTP:  true,
				UseSSL:  false,
				Dir:     ".",
				SSLCert: "cert.crt",
				SSLKey:  "cert.key",
			},
		},
		{
			name: "custom host",
			args: []string{"-host", "127.0.0.1"},
			expected: Config{
				Host:    "127.0.0.1",
				SSLHost: "",
				Port:    80,
				SSLPort: 0,
				NoHTTP:  false,
				UseSSL:  false,
				Dir:     ".",
				SSLCert: "cert.crt",
				SSLKey:  "cert.key",
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
			name: "ssl flag sets default port",
			config: Config{
				UseSSL:  true,
				SSLPort: 0,
			},
			expectedSSLPort: 443,
			expectedUseSSL:  true,
		},
		{
			name: "explicit ssl port enables ssl",
			config: Config{
				UseSSL:  false,
				SSLPort: 8443,
			},
			expectedSSLPort: 8443,
			expectedUseSSL:  true,
		},
		{
			name: "no ssl when port is 0 and flag not set",
			config: Config{
				UseSSL:  false,
				SSLPort: 0,
			},
			expectedSSLPort: 0,
			expectedUseSSL:  false,
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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Host     string
	SSLHost  string
	Port     int
	SSLPort  int
	NoHTTP   bool
	Dir      string
	SSLCert  string
	SSLKey   string
	SaveKeys bool
}

const (
	maxPort             = 1<<16 - 1
	serverReadTimeout   = 30 * time.Second
	serverWriteTimeout  = 30 * time.Second
	serverIdleTimeout   = 120 * time.Second
	serverShutdownLimit = 30 * time.Second
)

func DefaultConfig() *Config {
	return &Config{
		Host:     "",
		SSLHost:  "",
		Port:     80,
		SSLPort:  443,
		NoHTTP:   false,
		Dir:      ".",
		SSLCert:  "cert.crt",
		SSLKey:   "cert.key",
		SaveKeys: false,
	}
}

func (c *Config) ParseFlags(args []string) error {
	fs := flag.NewFlagSet("gomoose", flag.ContinueOnError)
	fs.StringVar(&c.Host, "host", c.Host, "HTTP host")
	fs.StringVar(&c.SSLHost, "sslhost", c.SSLHost, "SSL host")
	fs.IntVar(&c.Port, "port", c.Port, "HTTP port")
	fs.IntVar(&c.SSLPort, "sslport", c.SSLPort, "SSL port (0 to disable)")
	fs.BoolVar(&c.NoHTTP, "nohttp", c.NoHTTP, "Disable HTTP")
	fs.StringVar(&c.SSLCert, "cert", c.SSLCert, "SSL certificate file")
	fs.StringVar(&c.SSLKey, "key", c.SSLKey, "SSL key file")
	fs.StringVar(&c.Dir, "dir", c.Dir, "Directory to serve")
	fs.BoolVar(&c.SaveKeys, "savekeys", c.SaveKeys, "Save generated SSL files")
	return fs.Parse(args)
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.Port < 0 || c.Port > maxPort {
		return fmt.Errorf("HTTP port must be between 0 and %d, got %d", maxPort, c.Port)
	}
	if c.SSLPort < 0 || c.SSLPort > maxPort {
		return fmt.Errorf("SSL port must be between 0 and %d, got %d", maxPort, c.SSLPort)
	}
	if c.NoHTTP && c.SSLPort == 0 {
		return errors.New("at least one server must be enabled")
	}
	if c.SSLPort > 0 {
		if strings.TrimSpace(c.SSLCert) == "" {
			return errors.New("SSL certificate path cannot be empty")
		}
		if strings.TrimSpace(c.SSLKey) == "" {
			return errors.New("SSL key path cannot be empty")
		}
	}
	return nil
}

type Server struct {
	config      *Config
	httpServer  *http.Server
	tlsServer   *http.Server
	tlsConfig   *tls.Config
	blockedFile string
	mu          sync.RWMutex
}

func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Gomoose"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

func protectedFileHandler(handler http.Handler, blockedPath string, serverRoot string) http.Handler {
	rootPath := canonicalPath(serverRoot)
	blockedPath = canonicalPath(blockedPath)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := path.Clean("/" + r.URL.Path)
		relativePath := strings.TrimPrefix(cleanPath, "/")
		requestedPath := filepath.Clean(filepath.Join(rootPath, filepath.FromSlash(relativePath)))
		if !pathWithin(rootPath, requestedPath) {
			http.NotFound(w, r)
			return
		}

		if blockedPath != "" && samePath(requestedPath, blockedPath) {
			http.NotFound(w, r)
			return
		}

		if resolvedPath, err := filepath.EvalSymlinks(requestedPath); err == nil {
			resolvedPath = canonicalPath(resolvedPath)
			if !pathWithin(rootPath, resolvedPath) || (blockedPath != "" && samePath(resolvedPath, blockedPath)) {
				http.NotFound(w, r)
				return
			}
		}
		handler.ServeHTTP(w, r)
	})
}

func NewServer(config *Config) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Server{config: config}, nil
}

func (s *Server) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	rootPath, err := filepath.Abs(s.config.Dir)
	if err != nil {
		return fmt.Errorf("unable to resolve directory %s: %w", s.config.Dir, err)
	}
	rootPath, err = filepath.EvalSymlinks(rootPath)
	if err != nil {
		return fmt.Errorf("unable to resolve directory %s: %w", s.config.Dir, err)
	}
	info, err := os.Stat(rootPath)
	if err != nil {
		return fmt.Errorf("unable to access directory %s: %w", rootPath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("serving path %s is not a directory", rootPath)
	}

	log.Println("Serving", rootPath)

	if s.config.SSLKey != "" {
		keyPath, err := filepath.Abs(s.config.SSLKey)
		if err != nil {
			return fmt.Errorf("unable to resolve SSL key path %s: %w", s.config.SSLKey, err)
		}
		keyPath = canonicalPath(keyPath)
		if pathWithin(rootPath, keyPath) {
			s.blockedFile = keyPath
		}
	}

	baseHandler := http.FileServer(http.Dir(rootPath))
	handler := protectedFileHandler(baseHandler, s.blockedFile, rootPath)

	var tlsConfig *tls.Config
	if s.config.SSLPort > 0 {
		tlsConfig, err = s.loadTLSConfig()
		if err != nil {
			return err
		}
	}

	var httpListener net.Listener
	var tlsListener net.Listener
	closeListeners := func() {
		if httpListener != nil {
			_ = httpListener.Close()
		}
		if tlsListener != nil {
			_ = tlsListener.Close()
		}
	}

	if !s.config.NoHTTP {
		addr := net.JoinHostPort(s.config.Host, fmt.Sprintf("%d", s.config.Port))
		httpListener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("HTTP listener error: %w", err)
		}
	}

	if s.config.SSLPort > 0 {
		addr := net.JoinHostPort(s.config.SSLHost, fmt.Sprintf("%d", s.config.SSLPort))
		tlsListener, err = net.Listen("tcp", addr)
		if err != nil {
			closeListeners()
			return fmt.Errorf("HTTPS listener error: %w", err)
		}
		tlsListener = tls.NewListener(tlsListener, tlsConfig)
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 2)
	var httpServer *http.Server
	var tlsServer *http.Server

	if httpListener != nil {
		httpServer = newHTTPServer(httpListener.Addr().String(), handler, nil)
		log.Printf("HTTP listening on %s", httpServer.Addr)
	}
	if tlsListener != nil {
		tlsServer = newHTTPServer(tlsListener.Addr().String(), handler, tlsConfig)
		log.Printf("HTTPS listening on %s", tlsServer.Addr)
	}
	s.setServers(httpServer, tlsServer, tlsConfig)

	serve := func(server *http.Server, listener net.Listener, protocol string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- fmt.Errorf("%s server error: %w", protocol, err)
			}
		}()
	}
	if httpServer != nil {
		serve(httpServer, httpListener, "HTTP")
	}
	if tlsServer != nil {
		serve(tlsServer, tlsListener, "HTTPS")
	}

	select {
	case <-ctx.Done():
		log.Println("Shutting down servers...")
		s.Shutdown()
	case err := <-errChan:
		s.Shutdown()
		wg.Wait()
		return err
	}

	wg.Wait()
	log.Println("Done - exiting")
	return nil
}

func newHTTPServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
		MaxHeaderBytes:    1 << 20,
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func canonicalPath(path string) string {
	if path == "" {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	return filepath.Clean(path)
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func samePath(first, second string) bool {
	return first != "" && second != "" && canonicalPath(first) == canonicalPath(second)
}

func (s *Server) loadTLSConfig() (*tls.Config, error) {
	certPath, err := filepath.Abs(s.config.SSLCert)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve SSL certificate path %s: %w", s.config.SSLCert, err)
	}
	keyPath, err := filepath.Abs(s.config.SSLKey)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve SSL key path %s: %w", s.config.SSLKey, err)
	}

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)
	if certExists != keyExists {
		return nil, fmt.Errorf("SSL certificate and key must both exist (cert: %s, key: %s)", certPath, keyPath)
	}

	if certExists {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load SSL certificates: %w", err)
		}
		log.Printf("Using SSL certificate %s and key %s", certPath, keyPath)
		return newTLSConfig(cert), nil
	}

	log.Println("Generating self-signed certificate...")
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate self-signed certificate: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	if s.config.SaveKeys {
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			return nil, fmt.Errorf("failed to save certificate to %s: %w", certPath, err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return nil, fmt.Errorf("failed to save key to %s: %w", keyPath, err)
		}
		log.Printf("Saved certificate to %s", certPath)
		log.Printf("Saved key to %s", keyPath)
	}

	return newTLSConfig(cert), nil
}

func newTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
}

func (s *Server) setServers(httpServer, tlsServer *http.Server, tlsConfig *tls.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.httpServer = httpServer
	s.tlsServer = tlsServer
	s.tlsConfig = tlsConfig
}

func (s *Server) serverAddress(secure bool) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if secure {
		if s.tlsServer == nil {
			return ""
		}
		return s.tlsServer.Addr
	}
	if s.httpServer == nil {
		return ""
	}
	return s.httpServer.Addr
}

func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), serverShutdownLimit)
	defer cancel()

	s.mu.RLock()
	httpServer := s.httpServer
	tlsServer := s.tlsServer
	s.mu.RUnlock()

	if httpServer != nil {
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}
	if tlsServer != nil {
		if err := tlsServer.Shutdown(ctx); err != nil {
			log.Printf("HTTPS server shutdown error: %v", err)
		}
	}
}

func main() {
	config := DefaultConfig()
	if err := config.ParseFlags(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		log.Fatal(err)
	}

	server, err := NewServer(config)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	go func() {
		<-sigChan
		cancel()
	}()

	if err := server.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

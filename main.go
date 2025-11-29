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
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
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
	UseSSL   bool
	NoSSL    bool
	Dir      string
	SSLCert  string
	SSLKey   string
	SaveKeys bool
}

func DefaultConfig() *Config {
	return &Config{
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
	}
}

func (c *Config) ParseFlags(args []string) error {
	fs := flag.NewFlagSet("gomoose", flag.ContinueOnError)
	fs.StringVar(&c.Host, "host", c.Host, "HTTP host to listen on")
	fs.StringVar(&c.SSLHost, "sslhost", c.SSLHost, "SSL host to listen on")
	fs.IntVar(&c.Port, "port", c.Port, "HTTP port to listen on")
	fs.IntVar(&c.SSLPort, "sslport", c.SSLPort, "SSL port to listen on (0 to disable SSL)")
	fs.BoolVar(&c.NoHTTP, "nohttp", c.NoHTTP, "Disables HTTP")
	fs.BoolVar(&c.NoSSL, "nossl", c.NoSSL, "Disables SSL (SSL is enabled by default)")
	fs.StringVar(&c.SSLCert, "cert", c.SSLCert, "File to use as SSL cert (generated in memory if not found)")
	fs.StringVar(&c.SSLKey, "key", c.SSLKey, "File to use as SSL key (generated in memory if not found)")
	fs.StringVar(&c.Dir, "dir", c.Dir, "Directory to serve")
	fs.BoolVar(&c.SaveKeys, "savekeys", c.SaveKeys, "Save generated SSL cert and key files to disk")
	return fs.Parse(args)
}

func (c *Config) Validate() error {
	// Handle --nossl flag
	if c.NoSSL {
		c.UseSSL = false
		c.SSLPort = 0
	} else {
		// SSL is enabled by default
		c.UseSSL = c.SSLPort > 0
	}
	return nil
}

type Server struct {
	config      *Config
	httpServer  *http.Server
	tlsServer   *http.Server
	tlsConfig   *tls.Config
	blockedFile string // Absolute path of private key file to block
}

// generateSelfSignedCert generates a self-signed certificate and private key in memory
func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	// Generate ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Gomoose Self-Signed"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// protectedFileHandler wraps a file handler to block access to specific files
func protectedFileHandler(handler http.Handler, blockedPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clean the URL path to prevent path traversal
		cleanPath := filepath.Clean(r.URL.Path)
		if blockedPath != "" && strings.HasSuffix(blockedPath, cleanPath) {
			http.NotFound(w, r)
			return
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
	path, err := filepath.Abs(s.config.Dir)
	if err != nil {
		return fmt.Errorf("unable to resolve directory %s: %w", s.config.Dir, err)
	}

	log.Println("Serving", path)

	// Determine if we need to block the private key file
	if s.config.UseSSL {
		keyPath := s.config.SSLKey
		if !filepath.IsAbs(keyPath) {
			keyPath = filepath.Join(path, keyPath)
		}
		absKeyPath, err := filepath.Abs(keyPath)
		if err == nil && strings.HasPrefix(absKeyPath, path) {
			s.blockedFile = absKeyPath
		}
	}

	baseHandler := http.FileServer(http.Dir(path))
	handler := protectedFileHandler(baseHandler, s.blockedFile)

	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	if !s.config.NoHTTP {
		addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
		s.httpServer = &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		log.Printf("HTTP listening on %s", addr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTP server error: %w", err)
			}
		}()
	}

	if s.config.UseSSL {
		addr := fmt.Sprintf("%s:%d", s.config.SSLHost, s.config.SSLPort)

		// Check if cert/key files exist
		certExists := fileExists(s.config.SSLCert)
		keyExists := fileExists(s.config.SSLKey)

		var tlsConfig *tls.Config

		if certExists && keyExists {
			// Use existing cert/key files
			cert, err := tls.LoadX509KeyPair(s.config.SSLCert, s.config.SSLKey)
			if err != nil {
				return fmt.Errorf("failed to load SSL certificates: %w", err)
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
			log.Printf("HTTPS listening on %s (cert: %s, key: %s)", addr, s.config.SSLCert, s.config.SSLKey)
		} else {
			// Generate self-signed certificate in memory
			log.Println("SSL certificate files not found, generating self-signed certificate in memory...")
			certPEM, keyPEM, err := generateSelfSignedCert()
			if err != nil {
				return fmt.Errorf("failed to generate self-signed certificate: %w", err)
			}

			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return fmt.Errorf("failed to parse generated certificate: %w", err)
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}

			// Save keys if requested
			if s.config.SaveKeys {
				if err := os.WriteFile(s.config.SSLCert, certPEM, 0644); err != nil {
					log.Printf("Warning: failed to save certificate to %s: %v", s.config.SSLCert, err)
				} else {
					log.Printf("Saved certificate to %s", s.config.SSLCert)
				}
				if err := os.WriteFile(s.config.SSLKey, keyPEM, 0600); err != nil {
					log.Printf("Warning: failed to save key to %s: %v", s.config.SSLKey, err)
				} else {
					log.Printf("Saved key to %s", s.config.SSLKey)
				}
			}

			log.Printf("HTTPS listening on %s (using generated self-signed certificate)", addr)
		}

		s.tlsConfig = tlsConfig
		s.tlsServer = &http.Server{
			Addr:              addr,
			Handler:           handler,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			// Use ListenAndServeTLS with empty strings since we configured TLSConfig
			if err := s.tlsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTPS server error: %w", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		log.Println("Shutting down servers...")
		s.Shutdown()
	case err := <-errChan:
		return err
	}

	wg.Wait()
	log.Println("Done - exiting")
	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}
	if s.tlsServer != nil {
		if err := s.tlsServer.Shutdown(ctx); err != nil {
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
	go func() {
		<-sigChan
		cancel()
	}()

	if err := server.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

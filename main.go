package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Config holds the server configuration.
type Config struct {
	Host    string
	SSLHost string
	Port    int
	SSLPort int
	NoHTTP  bool
	UseSSL  bool
	Dir     string
	SSLCert string
	SSLKey  string
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Host:    "",
		SSLHost: "",
		Port:    80,
		SSLPort: 0,
		NoHTTP:  false,
		UseSSL:  false,
		Dir:     ".",
		SSLCert: "cert.crt",
		SSLKey:  "cert.key",
	}
}

// ParseFlags parses command line flags into the config.
func (c *Config) ParseFlags(args []string) error {
	fs := flag.NewFlagSet("gomoose", flag.ContinueOnError)
	fs.StringVar(&c.Host, "host", c.Host, "HTTP host to listen on")
	fs.StringVar(&c.SSLHost, "sslhost", c.SSLHost, "SSL host to listen on")
	fs.IntVar(&c.Port, "port", c.Port, "HTTP port to listen on")
	fs.IntVar(&c.SSLPort, "sslport", c.SSLPort, "SSL port to listen on")
	fs.BoolVar(&c.NoHTTP, "nohttp", c.NoHTTP, "Disables HTTP")
	fs.BoolVar(&c.UseSSL, "ssl", c.UseSSL, "Enables SSL (sets sslport to 443 if unspecified)")
	fs.StringVar(&c.SSLCert, "cert", c.SSLCert, "File to use as SSL cert")
	fs.StringVar(&c.SSLKey, "key", c.SSLKey, "File to use as SSL key")
	fs.StringVar(&c.Dir, "dir", c.Dir, "Directory to serve")
	return fs.Parse(args)
}

// Validate validates the configuration and applies defaults.
func (c *Config) Validate() error {
	// If SSL flag is set but no port specified, default to 443
	if c.SSLPort <= 0 && c.UseSSL {
		c.SSLPort = 443
	}
	// Enable SSL if a port is specified (allows -sslport without -ssl)
	c.UseSSL = c.SSLPort > 0
	return nil
}

// Server represents the web server.
type Server struct {
	config     *Config
	httpServer *http.Server
	tlsServer  *http.Server
}

// NewServer creates a new server with the given configuration.
func NewServer(config *Config) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Server{config: config}, nil
}

// Run starts the server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	path, err := filepath.Abs(s.config.Dir)
	if err != nil {
		return fmt.Errorf("unable to resolve directory %s: %w", s.config.Dir, err)
	}

	log.Println("Serving", path)
	handler := http.FileServer(http.Dir(path))

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
		s.tlsServer = &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		log.Printf("HTTPS listening on %s (cert: %s, key: %s)", addr, s.config.SSLCert, s.config.SSLKey)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.tlsServer.ListenAndServeTLS(s.config.SSLCert, s.config.SSLKey); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTPS server error: %w", err)
			}
		}()
	}

	// Wait for context cancellation or error
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

// Shutdown gracefully shuts down the servers.
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

	// Set up signal handling for graceful shutdown
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

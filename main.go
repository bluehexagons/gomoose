package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
)

var host = ""
var sslHost = ""
var port = 80
var sslPort = 0
var noHTTP = false
var useSSL = false
var dir = "."
var sslCert = "cert.crt"
var sslKey = "cert.key"

func init() {
	flag.StringVar(&host, "host", host, "HTTP host to listen on")
	flag.StringVar(&sslHost, "sslhost", sslHost, "SSL host to listen on")
	flag.IntVar(&port, "port", port, "HTTP port to listen on")
	flag.IntVar(&sslPort, "sslport", sslPort, "SSL port to listen on")
	flag.BoolVar(&noHTTP, "nohttp", noHTTP, "Disables HTTP")
	flag.BoolVar(&useSSL, "ssl", useSSL, "Enables SSL (sets sslport to 443 if unspecified)")
	flag.StringVar(&sslCert, "cert", sslCert, "File to use as SSL cert")
	flag.StringVar(&sslKey, "key", sslKey, "File to use as SSL key")
	flag.Parse()
}

func main() {
	if sslPort <= 0 && useSSL {
		sslPort = 443
	}
	useSSL = sslPort > 0

	path, err := filepath.Abs(dir)
	if err != nil {
		log.Fatal("Unable to resolve directory:", dir, err)
	}
	var wg sync.WaitGroup
	log.Println("Serving", path)
	handler := http.FileServer(http.Dir(path))
	if !noHTTP {
		log.Println("HTTP listening on port", port)
		wg.Add(1)
		go func() {
			err := http.ListenAndServe(host+":"+strconv.Itoa(port), handler)
			if err != nil {
				log.Println("HTTP listening error:", err)
			}
			wg.Done()
		}()
	}
	if useSSL {
		log.Printf("SSL listening on port %d (cert: %s, key: %s)", sslPort, sslCert, sslKey)
		go func() {
			err := http.ListenAndServeTLS(sslHost+":"+strconv.Itoa(sslPort), sslCert, sslKey, handler)
			wg.Add(1)
			if err != nil {
				log.Println("SSL listening error:", err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
	fmt.Println("Done - exiting")
}

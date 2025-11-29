# gomoose
Go Minimal Web Server - Go MWS - Gomoose

Approximately as basic as it can be while still having enough features to justify making it open source.

## Installation

Download the latest release for your platform from the [Releases](https://github.com/bluehexagons/gomoose/releases) page.

Or build from source:
```bash
go install github.com/bluehexagons/gomoose@latest
```

## Basic use

Gomoose defaults to serving the working directory over both HTTP (port 80) and HTTPS (port 443). SSL is enabled by default - if no certificate files are found, a self-signed certificate is automatically generated in memory.

To simply serve a directory, place the binary in a folder and run it (e.g. `./gomoose`). Note: Gomoose will also serve itself, but will block access to any active private key file being used for SSL.

Place binary in `/usr/local/bin/gomoose` to easily serve working directory.

Run with `gomoose -help` to view all command line options. Examples:
* `gomoose -nossl` will disable HTTPS and serve only over HTTP.
* `gomoose -nohttp` will disable HTTP and serve only over HTTPS.
* `gomoose -dir "/path/to/dir"` specifies what directory to serve (defaults to working directory).
* `gomoose -port 8080` specifies HTTP port to listen on.
* `gomoose -sslport 8443` specifies HTTPS port to listen on.
* `gomoose -savekeys` will save any newly generated SSL certificates to disk.

## SSL Certificates

SSL is enabled by default on port 443. If no certificate files (`cert.crt` and `cert.key`) are found, Gomoose automatically generates a self-signed certificate in memory.

To use your own certificates, either:

1. Place `cert.crt` and `cert.key` files in the working directory, or
2. Specify custom paths with `-cert` and `-key` flags:
   ```bash
   gomoose -cert /path/to/cert.crt -key /path/to/cert.key
   ```

To generate a self-signed certificate manually:
```bash
openssl req -newkey rsa:2048 -nodes -keyout cert.key -x509 -days 36525 -out cert.crt
```

To save auto-generated certificates to disk for reuse:
```bash
gomoose -savekeys
```

To disable SSL entirely:
```bash
gomoose -nossl
```

## Security

When SSL is enabled, Gomoose automatically blocks HTTP access to the active private key file to prevent accidental exposure of sensitive credentials.

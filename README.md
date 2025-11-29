# gomoose
Go Minimal Web Server - Go MWS - Gomoose

## Installation

```bash
go install github.com/bluehexagons/gomoose@latest
```

Or download from [Releases](https://github.com/bluehexagons/gomoose/releases).

## Usage

```bash
gomoose                    # Serve current directory on HTTP :80 and HTTPS :443
gomoose -port 8080         # Custom HTTP port
gomoose -sslport 0         # Disable HTTPS
gomoose -nohttp            # HTTPS only
gomoose -dir /path/to/www  # Serve specific directory
gomoose -savekeys          # Save generated SSL certificates
```

Run `gomoose -help` for all options.

## SSL

HTTPS is enabled by default. If no certificate files exist, a self-signed certificate is generated automatically. Place `cert.crt` and `cert.key` in the working directory or specify paths with `-cert` and `-key`.

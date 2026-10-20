# gomoose
Go Minimal Web Server - Go MWS - Gomoose

## Installation

Requires Go 1.26 or newer.

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

Certificate and key paths are resolved from the working directory. Private keys are never served when they are inside the configured content directory.

## Development

Basaltwater on Debian is the reference environment; Go 1.26+ and a C compiler
for race tests are sufficient without Basaltwater. From a checkout:

```bash
go build ./...
go test -race ./...
go vet ./...
```

For a local preview, select a directory containing only the intended web content
and bind an unprivileged port on loopback:

```bash
go run . -host 127.0.0.1 -port 8080 -sslport 0 -dir /absolute/path/to/site
```

Open <http://127.0.0.1:8080/>. This avoids binding ports 80/443 or creating
certificates for a local HTTP preview. For an authorized remote preview on
Basaltwater, follow the shared `basaltwater-web-gateway` skill to forward this
existing loopback service through managed HTTPS. Keep host setup and TLS
configuration out of project scripts. The
[shared project standards](https://github.com/bluehexagons/basaltwater/blob/main/docs/agents/project-standards.md)
also apply to agent work; native Go development remains independent.

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

Gomoose defaults to serving the working directory. So, to simply serve a directory over HTTP, place the binary in a folder and run it (e.g. `./gomoose`). Note: Gomoose will also serve itself.

Running with `gomoose -ssl -dir "/path/to/www"` with a cert.crt and cert.key in the working directory will enable an HTTPS server.

Running with `-ssl -nohttp` flags will disable the HTTP server.

Place binary in `/usr/local/bin/gomoose` to easily serve working directory.

Run with `gomoose -help` to view all command line options. Examples:
* `gomoose -ssl` will enable serving over HTTPS.
* `gomoose -dir "/path/to/dir"` specifies what directory to serve (defaults to working directory).
* `gomoose -port 8080` specifies port to listen on.

## SSL Certificates

To enable SSL, generate a certificate and key:

```bash
openssl req -newkey rsa:2048 -nodes -keyout cert.key -x509 -days 36525 -out cert.crt
```

Then run with the `-ssl` flag:
```bash
gomoose -ssl
```

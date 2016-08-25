# gomoose
Go Minimal Web Server - Go MWS - Gomoose

Run with `gomoose -help` to view all command line options. Examples:
* `gomoose -ssl` will enable serving over HTTPS.
* `gomoose -dir "/path/to/dir` specifies what directory to serve (defaults to working directory).
* `gomoose -port 8080` specifies port to listen on.

SSL certificate/key bundled for ease of use, but it's probably wise to generate a new one:

`openssl req -newkey rsa:2048 -nodes -keyout cert.key -x509 -days 36525 -out cert.crt`

The binary files with no platform specified (gomoose and gomoose-x86) are Linux binaries. The others were compiled for other platforms from a Linux system, and hopefully work.

# Basic use:
Gomoose defaults to serving the working directory. So, to simply serve a directory over HTTP, place the binary in a folder and run it (e.g. `./gomoose`). Note: Gomoose will also serve itself.

Running with `gomoose -ssl -dir "/path/to/www"` with a cert.crt and cert.key in the working directory will enable an HTTPS server.

Running with `-ssl -nohttp` flags will disable the HTTP server.

Place binary in `/usr/local/bin/gomoose` to easily serve working directory.

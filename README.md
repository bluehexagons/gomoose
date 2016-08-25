# gomoose
Go Minimal Web Server - Go MWS - Gomoose

Run with `gomoose -help` to view all command line options. Examples:
* `gomoose -ssl` will enable serving over HTTPS.
* `gomoose -dir "/path/to/dir` specifies what directory to serve (defaults to working directory).

SSL certificate/key bundled for ease of use, but it's probably wise to generate a new one:

`openssl req -newkey rsa:2048 -nodes -keyout cert.key -x509 -days 36525 -out cert.crt`

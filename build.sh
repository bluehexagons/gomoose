GOOS=windows GOARCH=386 go build -o bin/gomoose-x86.exe
GOOS=windows GOARCH=amd64 go build -o bin/gomoose.exe
GOOS=linux GOARCH=386 go build -o bin/gomoose-x86
GOOS=linux GOARCH=amd64 go build -o bin/gomoose
GOOS=darwin GOARCH=386 go build -o bin/gomoose-darwin-x86
GOOS=darwin GOARCH=amd64 go build -o bin/gomoose-darwin

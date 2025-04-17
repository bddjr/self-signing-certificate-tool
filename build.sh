set -e
cd $(dirname $0)
rm -rf dist

GOARCH=amd64 GOOS=windows go build -o dist/self-signing-certificate-tool-amd64.exe -trimpath -ldflags "-w -s"
GOARCH=amd64 GOOS=linux go build -o dist/self-signing-certificate-tool-linux-amd64 -trimpath -ldflags "-w -s"
GOARCH=amd64 GOOS=darwin go build -o dist/self-signing-certificate-tool-darwin-amd64 -trimpath -ldflags "-w -s"

GOARCH=arm64 GOOS=windows go build -o dist/self-signing-certificate-tool-arm64.exe -trimpath -ldflags "-w -s"
GOARCH=arm64 GOOS=linux go build -o dist/self-signing-certificate-tool-linux-arm64 -trimpath -ldflags "-w -s"
GOARCH=arm64 GOOS=darwin go build -o dist/self-signing-certificate-tool-darwin-arm64 -trimpath -ldflags "-w -s"

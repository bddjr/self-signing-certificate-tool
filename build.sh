set -e
cd $(dirname $0)
rm -rf dist wasm
mkdir wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" wasm/
GOOS=js GOARCH=wasm go build -o wasm/main.wasm -trimpath -ldflags "-w -s"
node build.js

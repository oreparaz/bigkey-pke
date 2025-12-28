# Big Key PKE

[![Tests](https://github.com/oreparaz/bigkey-pke/actions/workflows/test.yml/badge.svg)](https://github.com/oreparaz/bigkey-pke/actions/workflows/test.yml)

A public-key encryption system with short public keys and very long private keys, based on Identity-Based Encryption (IBE).

## Features

- **Short public keys**: Just the IBE master public key (~64 bytes)
- **Long private keys**: Collection of extracted identity keys (~100 bytes per identity)
- **Random identity selection**: Sender picks random identity from pre-agreed list
- **Forward secrecy**: Receiver can delete used keys after decryption
- **No master secret storage**: MSK is wiped after setup

## Installation

```bash
go get github.com/oreparaz/bigkey-pke/pkg/bigkey
```

See the [Makefile](Makefile) for useful development commands like `make test-quick`, `make build`, and `make run-example`.

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/oreparaz/bigkey-pke/pkg/bigkey"
)

func main() {
    // Setup: Generate key pair with 10,000 identities
    pubKey, privKey, err := bigkey.Setup(10000)
    if err != nil {
        log.Fatal(err)
    }

    // Encrypt a message
    identities := privKey.Identities
    message := []byte("Hello, World!")
    ciphertext, err := bigkey.Encrypt(pubKey, identities, message)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Encrypted to identity: %s\n", ciphertext.ID)

    // Decrypt the message
    plaintext, err := bigkey.Decrypt(privKey, ciphertext)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Decrypted: %s\n", string(plaintext))

    // Delete key for forward secrecy
    privKey.DeleteKey(ciphertext.ID)
}
```

## Project Structure

```
bigkey-pke/
├── pkg/
│   └── bigkey/              # Main library package
│       ├── bigkey.go        # Core implementation
│       └── *_test.go        # Test suites
├── internal/
│   └── testutil/            # Internal test utilities
├── cmd/
│   └── bigkey-demo/         # CLI demo tool
│       └── main.go
├── examples/
│   ├── basic/               # Basic usage
│   └── advanced/            # Advanced examples
├── docs/                    # Documentation
│   ├── BIGKEY_DESIGN.txt
│   ├── USAGE_GUIDE.md
│   ├── SECURITY_ANALYSIS.md
│   └── ...
├── go.mod
└── README.md
```

## Documentation

- **Design**: [docs/BIGKEY_DESIGN.txt](docs/BIGKEY_DESIGN.txt)

## Examples

### Run the demo CLI tool

```bash
go run ./cmd/bigkey-demo -identities 1000
```

### Basic example

```bash
cd examples/basic
go run main.go
```

### Bidirectional communication

```bash
cd examples/advanced
go run bidirectional.go
```

## Testing

### Using Make (Recommended)

```bash
# Quick tests (~25s, skips large-scale tests)
make test

# Full test suite (~400s, includes 100k identity tests)
make test-full
```

### Using Go Commands Directly

```bash
# Run quick tests (skips large-scale tests)
go test -short -v ./...

# Run all tests including large-scale
go test -v ./...
```

**Note**: The test suite includes large-scale tests (100,000 identities) that take ~6 minutes. Use `make test` or `go test -short` for faster feedback during development.

## Import Path

```go
import "github.com/oreparaz/bigkey-pke/pkg/bigkey"
```

The main package is `pkg/bigkey`. Internal utilities in `internal/` cannot be imported by external packages.

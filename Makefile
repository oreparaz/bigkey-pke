.PHONY: test test-quick test-full build clean run-example run-demo help

# Default target
help:
	@echo "Available targets:"
	@echo "  make test-quick    - Run fast tests (~25s, skips large-scale tests)"
	@echo "  make test-full     - Run all tests including large-scale (~400s)"
	@echo "  make test          - Alias for test-quick"
	@echo "  make build         - Build the demo CLI tool"
	@echo "  make run-example   - Run the basic example"
	@echo "  make run-demo      - Run the CLI demo tool"
	@echo "  make clean         - Clean build artifacts"

# Quick tests (default) - skips large-scale tests
test-quick:
	@echo "Running quick tests (skipping large-scale tests)..."
	go test -short -v ./...

# Alias: make test runs quick tests by default
test: test-quick

# Full test suite - runs all tests including large-scale
test-full:
	@echo "Running full test suite (including large-scale tests, ~400s)..."
	go test -v ./...

# Build the CLI demo tool
build:
	@echo "Building bigkey-demo..."
	@mkdir -p bin
	go build -o bin/bigkey-demo ./cmd/bigkey-demo
	@echo "Built: bin/bigkey-demo"

# Run the basic example
run-example:
	@echo "Running basic example..."
	go run ./examples/basic/main.go

# Run the CLI demo tool
run-demo:
	@echo "Running CLI demo..."
	go run ./cmd/bigkey-demo

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	@echo "Clean complete"

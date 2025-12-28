# Examples

This directory contains example programs demonstrating how to use the Big Key PKE library.

## Basic Example

The basic example (`basic/main.go`) demonstrates:
- Setting up a key pair
- Encrypting messages
- Decrypting messages
- Forward secrecy through key deletion

### Running

```bash
cd examples/basic
go run main.go
```

### Expected Output

```
=== Big Key Public-Key Encryption Demo ===

SETUP PHASE
-----------
Alice: Generating big key pair with 10000 identities...
Alice: Public key generated (MPK): 64 bytes
Alice: Private key generated (BigSK): ~10000 identity keys
...
```

## Advanced Example

The bidirectional example (`advanced/bidirectional.go`) demonstrates:
- Both parties having their own key pairs
- Two-way encrypted communication
- Managing multiple key pairs

### Running

```bash
cd examples/advanced
go run bidirectional.go
```

## Adding More Examples

To add a new example:

1. Create a new directory: `examples/your-example-name/`
2. Add `main.go` with your example code
3. Add a `README.md` explaining the example
4. Update this README with a link

## Example Ideas

- **Batch processing**: Encrypting/decrypting multiple messages efficiently
- **Integration**: Using with gRPC or HTTP APIs
- **Performance**: Benchmarking different identity space sizes
- **Multi-recipient**: Broadcasting to multiple recipients

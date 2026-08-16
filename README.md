# Go-SLIP10

🔐 **Universal Hierarchical Deterministic Key Derivation for Go**

[![Go Reference](https://pkg.go.dev/badge/github.com/meehow/go-slip10.svg)](https://pkg.go.dev/github.com/meehow/go-slip10)
[![Go Report Card](https://goreportcard.com/badge/github.com/meehow/go-slip10)](https://goreportcard.com/report/github.com/meehow/go-slip10)
[![Test](https://github.com/meehow/go-slip10/actions/workflows/test.yml/badge.svg)](https://github.com/meehow/go-slip10/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/meehow/go-slip10/branch/master/graph/badge.svg)](https://codecov.io/gh/meehow/go-slip10)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A robust, idiomatic Go library for **SLIP-10** (Universal Hierarchical Deterministic Key Derivation) and **BIP-39** (Mnemonic Codes).

---

`go-slip10` provides a unified interface to generate and derive keys across multiple elliptic curves, making it the perfect foundation for multi-chain wallets and cryptographic tools.

> **📋 Supported Standards**: While named after SLIP-10, this library implements **two** HD derivation standards:
> - **[SLIP-10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)**: Universal derivation for secp256k1 (Bitcoin/Ethereum), Ed25519 (Solana), NIST P-256, and Curve25519
> - **[Ed25519-BIP32 (CIP-3)](https://cips.cardano.org/cip/CIP-0003)**: Cardano's IOHK variant with 64-byte extended keys and public child derivation support

## ⚡ Quick Start

```go
import "github.com/meehow/go-slip10"

// Mnemonic → Seed → Master Key → Child Key in 3 lines
seed := slip10.MnemonicToSeed("abandon abandon abandon ... about", "")
master, _ := slip10.NewMasterNode(seed, slip10.NewSecp256k1())
child, _ := master.DerivePath("m/44'/0'/0'/0/0")
```

## 🚀 Key Features

- **Multi-Curve Support**: Native support for **secp256k1** (Bitcoin/Ethereum), **NIST P-256**, **Ed25519** (Solana), **Ed25519-BIP32** (Cardano), and **Curve25519**.
- **Standards Compliant**: Strictly follows [SLIP-10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md), [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), and [CIP-1852](https://cips.cardano.org/cip/CIP-1852) specifications.
- **Public Child Derivation (CKDpub)**: Full support for deriving public child keys from public parent keys for Weierstrass curves (`secp256k1`, `NIST P-256`) and Ed25519-BIP32, enabling secure watch-only architectures.
- **Verified Correctness**: Rigorously tested against official test vectors and reference implementations. **97% Test Coverage**.
- **High Performance**: Includes a custom, optimized Base58 implementation and minimal external dependencies.

## 🌍 Use Cases

- **Multi-chain HD Wallets**: Derive keys for Bitcoin, Ethereum, Solana, and more from a single mnemonic
- **Watch-Only Servers**: Use CKDpub to generate receiving addresses without exposing private keys
- **Hardware Wallet Integration**: Standard compliance ensures interoperability with Ledger/Trezor
- **Cold Storage Solutions**: Generate addresses offline with full derivation path control
- **Key Management Systems**: Programmatically manage hierarchical key structures

## ⚖️ Comparison

Why choose `go-slip10` over other libraries?

| Feature | `go-slip10` | `btcsuite/btcutil` | `anyproto/go-slip10` |
|:---|:---:|:---:|:---:|
| **SLIP-10 Support** | ✅ Native | ❌ BIP-32 only | ✅ Ed25519 only |
| **Multi-Curve** | ✅ 5 curves | ❌ Secp256k1 only | ❌ Ed25519 only |
| **BIP-39** | ✅ Built-in | ⚠️ Separate pkg | ❌ |
| **Cardano (CIP-1852)** | ✅ Ed25519-BIP32 | ❌ | ❌ |
| **Public Derivation** | ✅ Weierstrass + Ed25519-BIP32 | ✅ | ❌ |
| **Dependencies** | 🟢 Minimal | 🔴 Heavy | 🟢 Minimal |
| **Type Safety** | 🛡️ Strict | ⚠️ Loose | ⚠️ Loose |

## 📦 Installation

```bash
go get github.com/meehow/go-slip10
```

## 🛠️ Usage Examples

### 1. Mnemonic to Seed (BIP-39)

Convert a user-friendly mnemonic phrase into a binary seed for key derivation.

```go
package main

import (
    "fmt"
    "github.com/meehow/go-slip10"
)

func main() {
    mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    passphrase := "optional-passphrase"

    // Deterministically generate a 512-bit seed
    seed := slip10.MnemonicToSeed(mnemonic, passphrase)
    fmt.Printf("Seed: %x\n", seed)
}
```

### 2. Multi-Coin Derivation (SLIP-10)

Derive keys for different blockchains from the same master seed using different curves.

```go
// Create a Master Node for Bitcoin (secp256k1)
btcMaster, _ := slip10.NewMasterNode(seed, slip10.NewSecp256k1())
// Derive BIP-44 path: m/44'/0'/0'/0/0
btcChild, _ := btcMaster.DerivePath("m/44'/0'/0'/0/0")
fmt.Printf("BTC Private Key: %x\n", btcChild.PrivKey)

// Create a Master Node for Solana (Ed25519)
solMaster, _ := slip10.NewMasterNode(seed, slip10.NewEd25519())
// Derive path: m/44'/501'/0'/0' (Hardened only for Ed25519)
solChild, _ := solMaster.DerivePath("m/44'/501'/0'/0'")
fmt.Printf("SOL Private Key: %x\n", solChild.PrivKey)

// Create a Master Node for Cardano (Ed25519-BIP32)
adaMaster, _ := slip10.NewMasterNode(seed, slip10.NewEd25519Bip32())
// Derive CIP-1852 path: m/1852'/1815'/0'/0/0 (supports soft derivation)
adaPayment, _ := adaMaster.DerivePath("m/1852'/1815'/0'/0/0")
fmt.Printf("ADA Payment Key: %x\n", adaPayment.ExtendedPrivKey())
```

### 3. Public Child Derivation (Watch-Only Wallets)

Safely derive public keys on a server without ever exposing private keys.

```go
// Assume we have an account-level extended public key (xpub)
accountXPub := "xpub6C..." 
node, _ := slip10.NewNodeFromExtendedKey(accountXPub, slip10.NewSecp256k1())

// Derive receive address index 0 (public derivation)
childPub, _ := node.Derive(0) 

fmt.Printf("Derived Public Key: %x\n", childPub.PublicKey())
// Note: childPub.PrivKey is nil, ensuring security.
```

## 📈 Performance

Benchmarked on Intel Core i7-10510U @ 1.80GHz:

| Operation | Time | Memory | Allocations |
|:---|---:|---:|---:|
| Base58 Encode | 1.31 µs | 96 B | 2 |
| Base58 Decode | 776 ns | 32 B | 1 |
| Mnemonic to Seed | 1.13 ms | 1.4 KB | 12 |
| Master Node (secp256k1) | 30.8 µs | 1.2 KB | 10 |
| Derive (secp256k1) | 32.5 µs | 1.4 KB | 15 |
| Derive (Ed25519) | 21.4 µs | 1.1 KB | 10 |
| Derive (NIST P-256) | 15.8 µs | 1.9 KB | 22 |
| DerivePath (5 levels) | 242 µs | 7.4 KB | 82 |
| XPriv/XPub Serialization | 9.5 µs | 224 B | 2 |

Run benchmarks yourself:

```bash
go test -bench=. -benchmem ./...
```

## 🔒 Security & Design

- **Type Safety**: The API is designed to prevent common mistakes, such as attempting public derivation on curves that don't support it (like Ed25519).
- **Input Validation**: Imported extended keys are validated: private scalars must be in range for the curve, public keys must decode to a point on the curve, and unknown version bytes or malformed encodings are rejected.
- **Well-Audited Dependencies**: Cryptographic operations use `golang.org/x/crypto`, `decred/dcrd/dcrec/secp256k1`, and `filippo.io/edwards25519`.
- **Audit Friendly**: Clean, readable code structure with clear separation of curve logic.
- **Not Constant-Time**: Scalar arithmetic for BIP-32 child derivation uses Go's `math/big`, which is not constant-time. Do not use this library where an attacker can measure derivation timing across a trust boundary.
- **Best-Effort Wiping**: `Node.Wipe()` zeroes the node's private key and chain code, but copies of key material may remain in intermediate buffers or moved memory managed by the Go runtime.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

```bash
# Run tests
go test -race -v ./...

# Run benchmarks
go test -bench=. -benchmem ./...

# Run fuzzing
go test -fuzz=FuzzBase58 -fuzztime=30s ./...
```

For major changes, please open an issue first to discuss what you would like to change.

## 🙏 Acknowledgments

- [SLIP-10 Specification](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) by SatoshiLabs
- [BIP-39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) by Marek Palatinus et al.
- [BIP-32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) by Pieter Wuille

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

*If you find this library useful, please consider giving it a ⭐*

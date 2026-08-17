# go-slip10

[![Go Reference](https://pkg.go.dev/badge/github.com/meehow/go-slip10.svg)](https://pkg.go.dev/github.com/meehow/go-slip10)
[![Go Report Card](https://goreportcard.com/badge/github.com/meehow/go-slip10)](https://goreportcard.com/report/github.com/meehow/go-slip10)
[![Test](https://github.com/meehow/go-slip10/actions/workflows/test.yml/badge.svg)](https://github.com/meehow/go-slip10/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/meehow/go-slip10/branch/master/graph/badge.svg)](https://codecov.io/gh/meehow/go-slip10)

Hierarchical deterministic key derivation for Go, with BIP-39 mnemonic
support built in. Implements two derivation schemes:

- [SLIP-10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md):
  secp256k1, NIST P-256, Ed25519 and Curve25519
- [Ed25519-BIP32 (CIP-3)](https://cips.cardano.org/cip/CIP-0003): Cardano's
  variant with 64-byte extended keys and soft (public) child derivation

Public child derivation (CKDpub) works for the Weierstrass curves and
Ed25519-BIP32, so watch-only setups can derive addresses without private
keys. Everything is tested against the official SLIP-10 vectors, Ledger's
HDEd25519 reference and the IntersectMBO/cardano-crypto vectors.

## Installation

```bash
go get github.com/meehow/go-slip10
```

## Usage

From mnemonic to child key:

```go
seed := slip10.MnemonicToSeed("abandon abandon ... about", "")
master, err := slip10.NewMasterNode(seed, slip10.NewSecp256k1())
if err != nil {
	log.Fatal(err)
}
child, err := master.DerivePath("m/44'/0'/0'/0/0")
```

The same seed works across curves, so one mnemonic can back keys for
several chains:

```go
btc, _ := slip10.NewMasterNode(seed, slip10.NewSecp256k1())
sol, _ := slip10.NewMasterNode(seed, slip10.NewEd25519())
ada, _ := slip10.NewMasterNode(seed, slip10.NewEd25519Bip32())

btcChild, _ := btc.DerivePath("m/44'/0'/0'/0/0")
solChild, _ := sol.DerivePath("m/44'/501'/0'/0'") // ed25519 is hardened-only
adaChild, _ := ada.DerivePath("m/1852'/1815'/0'/0/0")
```

Watch-only derivation from an xpub:

```go
node, err := slip10.NewNodeFromExtendedKey("xpub6C...", slip10.NewSecp256k1())
if err != nil {
	log.Fatal(err)
}
child, err := node.Derive(0) // child.PrivKey is nil
```

Ed25519-BIP32 keys serialize as bech32 instead of base58; `XPriv()` and
`XPub()` emit `xprv`/`xpub` prefixes and `NewNodeFromExtendedKey` also
accepts the CIP-5 prefixes (`root_xsk`, `acct_xvk`, ...).

See the [package documentation](https://pkg.go.dev/github.com/meehow/go-slip10)
for runnable examples.

## Security notes

- Imported extended keys are validated: private scalars must be in range
  for the curve, public keys must decode to a point on the curve, and
  unknown version bytes or malformed encodings are rejected.
- The API stops you from doing things the schemes don't allow, e.g.
  public derivation on plain Ed25519 or hardened derivation from an xpub.
- Scalar arithmetic for BIP-32 child derivation uses `math/big`, which is
  not constant-time. Don't use this library where an attacker can measure
  derivation timing across a trust boundary.
- `Node.Wipe()` zeroes the node's private key and chain code, but this is
  best-effort: the Go runtime may keep copies of key material in
  intermediate buffers or moved memory.
- Crypto primitives come from `golang.org/x/crypto`,
  `decred/dcrd/dcrec/secp256k1` and `filippo.io/edwards25519`.

## Development

```bash
go test -race ./...
go test -bench=. -benchmem ./...
go test -fuzz=FuzzBase58 -fuzztime=30s ./base58
```

## License

MIT, see [LICENSE](LICENSE).

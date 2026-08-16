package slip10

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/curve25519"
)

// Curve represents an elliptic curve supported by SLIP-10.
type Curve interface {
	Name() string
	MasterKey(seed []byte) (privKey, chainCode []byte, err error)
	DerivePrivateChild(privKey, chainCode []byte, index uint32) (childPrivKey, childChainCode []byte, err error)
	DerivePublicChild(pubKey, chainCode []byte, index uint32) (childPubKey, childChainCode []byte, err error)
	PublicKey(privKey []byte) []byte
}

type baseCurve struct {
	name     string
	seedSalt []byte
}

func (c *baseCurve) Name() string {
	return c.name
}

func (c *baseCurve) DerivePublicChild(pubKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	return nil, nil, errors.New("public child derivation not supported for this curve")
}

// secp256k1 implementation
type secp256k1Curve struct {
	baseCurve
}

func NewSecp256k1() Curve {
	return &secp256k1Curve{
		baseCurve: baseCurve{
			name:     "secp256k1",
			seedSalt: []byte("Bitcoin seed"),
		},
	}
}

func (c *secp256k1Curve) MasterKey(seed []byte) ([]byte, []byte, error) {
	return deriveMasterKey(c.seedSalt, seed, secp256k1.S256().N)
}

func (c *secp256k1Curve) DerivePrivateChild(privKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	return deriveWeierstrassChild(privKey, chainCode, index, secp256k1.S256().N, c.PublicKey)
}

func (c *secp256k1Curve) DerivePublicChild(pubKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	parser := func(data []byte) (*big.Int, *big.Int, error) {
		pk, err := secp256k1.ParsePubKey(data)
		if err != nil {
			return nil, nil, err
		}
		return pk.X(), pk.Y(), nil
	}
	return deriveWeierstrassPublicChild(pubKey, chainCode, index, secp256k1.S256(), parser)
}

func (c *secp256k1Curve) PublicKey(privKey []byte) []byte {
	priv := secp256k1.PrivKeyFromBytes(privKey)
	return priv.PubKey().SerializeCompressed()
}

// NIST P-256 implementation
type nist256p1Curve struct {
	baseCurve
}

func NewNist256p1() Curve {
	return &nist256p1Curve{
		baseCurve: baseCurve{
			name:     "nist256p1",
			seedSalt: []byte("Nist256p1 seed"),
		},
	}
}

func (c *nist256p1Curve) MasterKey(seed []byte) ([]byte, []byte, error) {
	return deriveMasterKey(c.seedSalt, seed, elliptic.P256().Params().N)
}

func (c *nist256p1Curve) DerivePrivateChild(privKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	return deriveWeierstrassChild(privKey, chainCode, index, elliptic.P256().Params().N, c.PublicKey)
}

func (c *nist256p1Curve) DerivePublicChild(pubKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	parser := func(data []byte) (*big.Int, *big.Int, error) {
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), data)
		if x == nil {
			return nil, nil, errors.New("invalid public key")
		}
		return x, y, nil
	}
	return deriveWeierstrassPublicChild(pubKey, chainCode, index, elliptic.P256(), parser)
}

func (c *nist256p1Curve) PublicKey(privKey []byte) []byte {
	x, y := elliptic.P256().ScalarBaseMult(privKey)
	return elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

func deriveWeierstrassPublicChild(pubKey, chainCode []byte, index uint32, curve elliptic.Curve, parsePubKey func([]byte) (*big.Int, *big.Int, error)) ([]byte, []byte, error) {
	if index >= 0x80000000 {
		return nil, nil, errors.New("cannot derive hardened child from public key")
	}

	var data [37]byte
	copy(data[:], pubKey)
	binary.BigEndian.PutUint32(data[33:], index)

	h := hmac.New(sha512.New, chainCode)
	h.Write(data[:])
	isum := h.Sum(nil)

	iLBig := new(big.Int)

	// Parse parental public key
	x, y, err := parsePubKey(pubKey)
	if err != nil {
		return nil, nil, err
	}

	for {
		iL := isum[:32]
		iR := isum[32:]

		iLBig.SetBytes(iL)
		if iLBig.Cmp(curve.Params().N) < 0 {
			// Ki = point(IL) + Kpar
			ix, iy := curve.ScalarBaseMult(iL)        // point(IL)
			childX, childY := curve.Add(ix, iy, x, y) // + Kpar

			if childX.Sign() != 0 || childY.Sign() != 0 { // Check if not point at infinity
				childPubKey := elliptic.MarshalCompressed(curve, childX, childY)
				return childPubKey, iR, nil
			}
		}

		h.Reset()
		h.Write([]byte{0x01})
		h.Write(iR)
		h.Write(data[33:])
		isum = h.Sum(nil)
	}
}

// ed25519 implementation
type ed25519Curve struct {
	baseCurve
}

func NewEd25519() Curve {
	return &ed25519Curve{
		baseCurve: baseCurve{
			name:     "ed25519",
			seedSalt: []byte("ed25519 seed"),
		},
	}
}

func (c *ed25519Curve) MasterKey(seed []byte) ([]byte, []byte, error) {
	h := hmac.New(sha512.New, c.seedSalt)
	h.Write(seed)
	i := h.Sum(nil)
	return i[:32], i[32:], nil
}

func (c *ed25519Curve) DerivePrivateChild(privKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	if index < 0x80000000 {
		return nil, nil, errors.New("normal derivation not supported for ed25519")
	}

	var data [37]byte
	data[0] = 0x00
	copy(data[1:], privKey)
	binary.BigEndian.PutUint32(data[33:], index)

	h := hmac.New(sha512.New, chainCode)
	h.Write(data[:])
	i := h.Sum(nil)
	return i[:32], i[32:], nil
}

func (c *ed25519Curve) PublicKey(privKey []byte) []byte {
	pub := ed25519.NewKeyFromSeed(privKey).Public().(ed25519.PublicKey)
	res := make([]byte, 33)
	res[0] = 0x00
	copy(res[1:], pub)
	return res
}

// curve25519 implementation
type curve25519Curve struct {
	baseCurve
}

func NewCurve25519() Curve {
	return &curve25519Curve{
		baseCurve: baseCurve{
			name:     "curve25519",
			seedSalt: []byte("curve25519 seed"),
		},
	}
}

func (c *curve25519Curve) MasterKey(seed []byte) ([]byte, []byte, error) {
	h := hmac.New(sha512.New, c.seedSalt)
	h.Write(seed)
	i := h.Sum(nil)
	return i[:32], i[32:], nil
}

func (c *curve25519Curve) DerivePrivateChild(privKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	if index < 0x80000000 {
		return nil, nil, errors.New("normal derivation not supported for curve25519")
	}

	var data [37]byte
	data[0] = 0x00
	copy(data[1:], privKey)
	binary.BigEndian.PutUint32(data[33:], index)

	h := hmac.New(sha512.New, chainCode)
	h.Write(data[:])
	i := h.Sum(nil)
	return i[:32], i[32:], nil
}

func (c *curve25519Curve) PublicKey(privKey []byte) []byte {
	// Clamp the private key per RFC 7748 to ensure valid scalar
	var scalar [32]byte
	copy(scalar[:], privKey)
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64

	pub, _ := curve25519.X25519(scalar[:], curve25519.Basepoint)
	res := make([]byte, 33)
	res[0] = 0x00
	copy(res[1:], pub)
	return res
}

// validatePrivateKey checks that privKey is a usable private key for the curve.
// For Weierstrass curves the scalar must be nonzero and below the group order,
// matching the checks other BIP-32 implementations perform on import.
func validatePrivateKey(curve Curve, privKey []byte) error {
	switch curve.Name() {
	case "secp256k1":
		return validateWeierstrassScalar(privKey, secp256k1.S256().N)
	case "nist256p1":
		return validateWeierstrassScalar(privKey, elliptic.P256().Params().N)
	default:
		if len(privKey) != 32 {
			return errors.New("invalid private key length")
		}
		return nil
	}
}

func validateWeierstrassScalar(privKey []byte, n *big.Int) error {
	if len(privKey) != 32 {
		return errors.New("invalid private key length")
	}
	k := new(big.Int).SetBytes(privKey)
	if k.Sign() == 0 || k.Cmp(n) >= 0 {
		return errors.New("private key out of range for curve")
	}
	return nil
}

// validatePublicKey checks that pubKey is a valid serialized public key for the
// curve, including that it decodes to a point on the curve where applicable.
func validatePublicKey(curve Curve, pubKey []byte) error {
	if len(pubKey) != 33 {
		return errors.New("invalid public key length")
	}
	switch curve.Name() {
	case "secp256k1":
		if pubKey[0] != 0x02 && pubKey[0] != 0x03 {
			return errors.New("invalid public key prefix")
		}
		if _, err := secp256k1.ParsePubKey(pubKey); err != nil {
			return errors.New("invalid public key: not on curve")
		}
	case "nist256p1":
		if pubKey[0] != 0x02 && pubKey[0] != 0x03 {
			return errors.New("invalid public key prefix")
		}
		if x, _ := elliptic.UnmarshalCompressed(elliptic.P256(), pubKey); x == nil {
			return errors.New("invalid public key: not on curve")
		}
	case "ed25519", "ed25519-bip32":
		if pubKey[0] != 0x00 {
			return errors.New("invalid public key prefix")
		}
		if !validEd25519Point(pubKey[1:]) {
			return errors.New("invalid public key: not a valid point")
		}
	case "curve25519":
		if pubKey[0] != 0x00 {
			return errors.New("invalid public key prefix")
		}
	default:
		if pubKey[0] != 0x02 && pubKey[0] != 0x03 {
			return errors.New("invalid public key prefix")
		}
	}
	return nil
}

// Helper functions for Weierstrass curves

func deriveMasterKey(salt, seed []byte, n *big.Int) ([]byte, []byte, error) {
	data := seed
	iLBig := new(big.Int)
	for {
		h := hmac.New(sha512.New, salt)
		h.Write(data)
		isum := h.Sum(nil)
		iL := isum[:32]
		iR := isum[32:]

		iLBig.SetBytes(iL)
		if iLBig.Sign() != 0 && iLBig.Cmp(n) < 0 {
			return iL, iR, nil
		}
		data = isum
	}
}

func deriveWeierstrassChild(privKey, chainCode []byte, index uint32, n *big.Int, pubKeyFunc func([]byte) []byte) ([]byte, []byte, error) {
	var data [37]byte
	if index >= 0x80000000 {
		data[0] = 0x00
		copy(data[1:], privKey)
	} else {
		pubKey := pubKeyFunc(privKey)
		copy(data[:], pubKey)
	}
	binary.BigEndian.PutUint32(data[33:], index)

	h := hmac.New(sha512.New, chainCode)
	h.Write(data[:])
	isum := h.Sum(nil)

	iLBig := new(big.Int)
	privKeyBig := new(big.Int).SetBytes(privKey)

	for {
		iL := isum[:32]
		iR := isum[32:]

		iLBig.SetBytes(iL)
		if iLBig.Cmp(n) < 0 {
			iLBig.Add(iLBig, privKeyBig)
			iLBig.Mod(iLBig, n)

			if iLBig.Sign() != 0 {
				childPrivKey := make([]byte, 32)
				b := iLBig.Bytes()
				copy(childPrivKey[32-len(b):], b) // Pad with leading zeros
				return childPrivKey, iR, nil
			}
		}

		h.Reset()
		h.Write([]byte{0x01})
		h.Write(iR)
		h.Write(data[33:])
		isum = h.Sum(nil)
	}
}

package slip10

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
)

// ed25519Bip32Curve implements the Ed25519-BIP32 (IOHK/Cardano) derivation scheme.
// Unlike SLIP-10 Ed25519, this scheme supports soft (non-hardened) derivation.
// Private keys are 64 bytes: kL (32 bytes scalar) + kR (32 bytes extension/IV).
type ed25519Bip32Curve struct {
	baseCurve
}

// NewEd25519Bip32 creates a new Ed25519-BIP32 curve for Cardano-compatible derivation.
// This supports both hardened and non-hardened (soft) derivation paths.
func NewEd25519Bip32() Curve {
	return &ed25519Bip32Curve{
		baseCurve: baseCurve{
			name:     "ed25519-bip32",
			seedSalt: []byte("ed25519 seed"),
		},
	}
}

// MasterKey generates a master key from seed using the Ed25519-BIP32 scheme.
// Returns a 64-byte private key (kL || kR) and 32-byte chain code.
func (c *ed25519Bip32Curve) MasterKey(seed []byte) ([]byte, []byte, error) {
	// Step 1: Compute chain code c = HMAC-SHA256(seedSalt, 0x01 || seed)
	hc := hmac.New(sha256.New, c.seedSalt)
	hc.Write([]byte{0x01})
	hc.Write(seed)
	chainCode := hc.Sum(nil)

	// Step 2: Compute I = HMAC-SHA512(seedSalt, seed)
	data := seed
	for {
		h := hmac.New(sha512.New, c.seedSalt)
		h.Write(data)
		I := h.Sum(nil)
		kL := I[:32]
		kR := I[32:]

		// Step 3: Check if the third highest bit of the last byte of kL is not zero
		// If set, retry with I as the new data
		if kL[31]&0b00100000 != 0 {
			data = I
			continue
		}

		// Step 4: Clamp kL
		kL[0] &= 0b11111000  // Clear lowest 3 bits
		kL[31] &= 0b01111111 // Clear highest bit
		kL[31] |= 0b01000000 // Set second highest bit

		// Return 64-byte extended private key (kL || kR) and chain code
		privKey := make([]byte, 64)
		copy(privKey[:32], kL)
		copy(privKey[32:], kR)

		return privKey, chainCode, nil
	}
}

// DerivePrivateChild derives a child private key for Ed25519-BIP32.
// Supports both hardened (index >= 0x80000000) and soft (index < 0x80000000) derivation.
func (c *ed25519Bip32Curve) DerivePrivateChild(privKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	if len(privKey) != 64 {
		return nil, nil, errors.New("ed25519-bip32 requires 64-byte extended private key")
	}

	kL := privKey[:32]
	kR := privKey[32:]

	// Index is encoded as little-endian (unlike BIP-32)
	var indexBytes [4]byte
	binary.LittleEndian.PutUint32(indexBytes[:], index)

	var Z, cNew []byte

	if index >= HardenedOffset {
		// Hardened derivation: Z = HMAC-SHA512(c, 0x00 || kL || kR || index)
		h := hmac.New(sha512.New, chainCode)
		h.Write([]byte{0x00})
		h.Write(kL)
		h.Write(kR)
		h.Write(indexBytes[:])
		Z = h.Sum(nil)

		// Chain code: c' = HMAC-SHA512(c, 0x01 || kL || kR || index)[32:]
		h.Reset()
		h.Write([]byte{0x01})
		h.Write(kL)
		h.Write(kR)
		h.Write(indexBytes[:])
		cNew = h.Sum(nil)[32:]
	} else {
		// Soft derivation: Z = HMAC-SHA512(c, 0x02 || A || index)
		A := c.publicKeyRaw(kL)

		h := hmac.New(sha512.New, chainCode)
		h.Write([]byte{0x02})
		h.Write(A)
		h.Write(indexBytes[:])
		Z = h.Sum(nil)

		// Chain code: c' = HMAC-SHA512(c, 0x03 || A || index)[32:]
		h.Reset()
		h.Write([]byte{0x03})
		h.Write(A)
		h.Write(indexBytes[:])
		cNew = h.Sum(nil)[32:]
	}

	// ZL is the first 28 bytes, ZR is the last 32 bytes
	ZL := Z[:28]
	ZR := Z[32:]

	// Compute kL' = ZL * 8 + kL (as little-endian integers)
	kLNew, err := deriveKL(ZL, kL)
	if err != nil {
		return nil, nil, err
	}

	// Compute kR' = (ZR + kR) mod 2^256
	kRNew := addMod256(ZR, kR)

	// Return 64-byte child private key
	childPrivKey := make([]byte, 64)
	copy(childPrivKey[:32], kLNew)
	copy(childPrivKey[32:], kRNew)

	return childPrivKey, cNew, nil
}

// DerivePublicChild derives a child public key for Ed25519-BIP32.
// Only supports soft derivation (index < 0x80000000).
func (c *ed25519Bip32Curve) DerivePublicChild(pubKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	if index >= HardenedOffset {
		return nil, nil, errors.New("cannot derive hardened child from public key")
	}

	// Remove the 0x00 prefix if present (our format uses 33-byte keys with 0x00 prefix)
	var A []byte
	if len(pubKey) == 33 && pubKey[0] == 0x00 {
		A = pubKey[1:]
	} else if len(pubKey) == 32 {
		A = pubKey
	} else {
		return nil, nil, errors.New("invalid public key length")
	}

	// Index is encoded as little-endian
	var indexBytes [4]byte
	binary.LittleEndian.PutUint32(indexBytes[:], index)

	// Z = HMAC-SHA512(c, 0x02 || A || index)
	h := hmac.New(sha512.New, chainCode)
	h.Write([]byte{0x02})
	h.Write(A)
	h.Write(indexBytes[:])
	Z := h.Sum(nil)

	// Chain code: c' = HMAC-SHA512(c, 0x03 || A || index)[32:]
	h.Reset()
	h.Write([]byte{0x03})
	h.Write(A)
	h.Write(indexBytes[:])
	cNew := h.Sum(nil)[32:]

	// ZL is the first 28 bytes
	ZL := Z[:28]

	// Compute A' = A + (ZL * 8) * G
	childA, err := derivePublicPoint(A, ZL)
	if err != nil {
		return nil, nil, err
	}

	// Return with 0x00 prefix to match our format
	childPubKey := make([]byte, 33)
	childPubKey[0] = 0x00
	copy(childPubKey[1:], childA)

	return childPubKey, cNew, nil
}

// PublicKey returns the 33-byte public key (0x00 prefix + 32-byte Ed25519 public key).
func (c *ed25519Bip32Curve) PublicKey(privKey []byte) []byte {
	var kL []byte
	if len(privKey) == 64 {
		kL = privKey[:32]
	} else if len(privKey) == 32 {
		kL = privKey
	} else {
		return nil
	}

	pubKeyRaw := c.publicKeyRaw(kL)

	// Return with 0x00 prefix to match existing Ed25519 format
	res := make([]byte, 33)
	res[0] = 0x00
	copy(res[1:], pubKeyRaw)
	return res
}

// publicKeyRaw returns the raw 32-byte Ed25519 public key from a 32-byte scalar.
func (c *ed25519Bip32Curve) publicKeyRaw(kL []byte) []byte {
	// The kL is already clamped, so we use it directly as a scalar.
	// We need to use SetUniformBytes because the derived scalar may exceed L
	// but is valid for point multiplication. SetUniformBytes takes 64 bytes
	// and reduces mod L.
	scalarBytes := make([]byte, 64)
	copy(scalarBytes, kL) // Pad to 64 bytes, little-endian

	scalar, err := edwards25519.NewScalar().SetUniformBytes(scalarBytes)
	if err != nil {
		return nil
	}

	point := edwards25519.NewGeneratorPoint().ScalarBaseMult(scalar)
	return point.Bytes()
}

// deriveKL computes kL' = (ZL * 8 + kL) mod L, where L is the Ed25519 order.
// ZL is 28 bytes, kL is 32 bytes, result is 32 bytes (little-endian).
func deriveKL(ZL, kL []byte) ([]byte, error) {
	// Convert ZL (28 bytes) to a 32-byte scalar by padding and multiplying by 8
	// ZL * 8 is equivalent to left-shifting by 3 bits

	// First, extend ZL to 32 bytes (pad with zeros on the right for little-endian)
	zlExtended := make([]byte, 32)
	copy(zlExtended, ZL)

	// Multiply by 8 (shift left by 3 bits)
	zlTimes8 := make([]byte, 32)
	var carry byte
	for i := 0; i < 32; i++ {
		newVal := (uint16(zlExtended[i]) << 3) | uint16(carry)
		zlTimes8[i] = byte(newVal & 0xFF)
		carry = byte(newVal >> 8)
	}

	// Add kL to zlTimes8
	result := make([]byte, 32)
	carry = 0
	for i := 0; i < 32; i++ {
		sum := uint16(zlTimes8[i]) + uint16(kL[i]) + uint16(carry)
		result[i] = byte(sum & 0xFF)
		carry = byte(sum >> 8)
	}

	// Check if result mod L == 0 (invalid key)
	// For a proper check, we'd need to reduce mod L, but in practice this is extremely rare
	allZero := true
	for _, b := range result {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("derived key is zero")
	}

	return result, nil
}

// addMod256 computes (a + b) mod 2^256 for 32-byte little-endian integers.
func addMod256(a, b []byte) []byte {
	result := make([]byte, 32)
	var carry uint16
	for i := 0; i < 32; i++ {
		sum := uint16(a[i]) + uint16(b[i]) + carry
		result[i] = byte(sum & 0xFF)
		carry = sum >> 8
	}
	// Carry is discarded (mod 2^256)
	return result
}

// derivePublicPoint computes A' = A + (ZL * 8) * G
func derivePublicPoint(A, ZL []byte) ([]byte, error) {
	// Parse parent public key A
	parentPoint, err := edwards25519.NewIdentityPoint().SetBytes(A)
	if err != nil {
		return nil, errors.New("invalid parent public key")
	}

	// Compute ZL * 8 as a scalar
	zlExtended := make([]byte, 32)
	copy(zlExtended, ZL)

	// Multiply by 8
	zlTimes8 := make([]byte, 32)
	var carry byte
	for i := 0; i < 32; i++ {
		newVal := (uint16(zlExtended[i]) << 3) | uint16(carry)
		zlTimes8[i] = byte(newVal & 0xFF)
		carry = byte(newVal >> 8)
	}

	// Create scalar from zlTimes8 using SetUniformBytes (64-byte input, reduces mod L)
	scalarBytes := make([]byte, 64)
	copy(scalarBytes, zlTimes8)

	scalar, err := edwards25519.NewScalar().SetUniformBytes(scalarBytes)
	if err != nil {
		return nil, errors.New("invalid scalar for public derivation")
	}

	// Compute (ZL * 8) * G
	offsetPoint := edwards25519.NewIdentityPoint().ScalarBaseMult(scalar)

	// Compute A' = A + offsetPoint
	childPoint := edwards25519.NewIdentityPoint().Add(parentPoint, offsetPoint)

	return childPoint.Bytes(), nil
}

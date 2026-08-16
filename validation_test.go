package slip10

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/meehow/go-slip10/bech32"
)

func testSeed(t *testing.T) []byte {
	t.Helper()
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

// Wiping a private node must not corrupt a previously neutered node.
func TestNeuterIndependentOfWipe(t *testing.T) {
	for _, curve := range []Curve{NewSecp256k1(), NewNist256p1(), NewEd25519Bip32()} {
		node, err := NewMasterNode(testSeed(t), curve)
		if err != nil {
			t.Fatalf("%s: %v", curve.Name(), err)
		}
		pub := node.Neuter()
		chainCode := append([]byte(nil), pub.ChainCode...)
		pubKey := append([]byte(nil), pub.PubKey...)

		node.Wipe()

		if !bytes.Equal(chainCode, pub.ChainCode) {
			t.Errorf("%s: neutered chain code changed by parent Wipe", curve.Name())
		}
		if !bytes.Equal(pubKey, pub.PubKey) {
			t.Errorf("%s: neutered public key changed by parent Wipe", curve.Name())
		}
	}
}

// XPub output must be importable again for every curve.
func TestXPubRoundTripAllCurves(t *testing.T) {
	for _, curve := range []Curve{NewSecp256k1(), NewNist256p1(), NewEd25519(), NewCurve25519(), NewEd25519Bip32()} {
		node, err := NewMasterNode(testSeed(t), curve)
		if err != nil {
			t.Fatalf("%s: %v", curve.Name(), err)
		}
		xpub := node.XPub()
		imported, err := NewNodeFromExtendedKey(xpub, curve)
		if err != nil {
			t.Errorf("%s: failed to re-import own XPub: %v", curve.Name(), err)
			continue
		}
		if imported.IsPrivate {
			t.Errorf("%s: imported xpub should be public-only", curve.Name())
		}
		if !bytes.Equal(imported.PubKey, node.PubKey) {
			t.Errorf("%s: public key mismatch after round trip", curve.Name())
		}
	}
}

// Derivation must stop at depth 255 instead of wrapping around to 0.
func TestDeriveMaxDepth(t *testing.T) {
	node, err := NewMasterNode(testSeed(t), NewSecp256k1())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 255; i++ {
		node, err = node.Derive(0)
		if err != nil {
			t.Fatalf("derivation at depth %d failed: %v", i, err)
		}
	}
	if node.Depth != 255 {
		t.Fatalf("expected depth 255, got %d", node.Depth)
	}
	if _, err := node.Derive(0); err == nil {
		t.Error("expected error when deriving beyond depth 255")
	}
}

// Extended private keys with out-of-range scalars must be rejected on import.
func TestImportRejectsInvalidScalar(t *testing.T) {
	curve := NewSecp256k1()
	node, err := NewMasterNode(testSeed(t), curve)
	if err != nil {
		t.Fatal(err)
	}

	secpN, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	cases := []struct {
		name string
		key  []byte
	}{
		{"zero scalar", make([]byte, 32)},
		{"scalar equal to group order", secpN},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forged := *node
			forged.PrivKey = tc.key
			if _, err := NewNodeFromExtendedKey(forged.XPriv(), curve); err == nil {
				t.Errorf("expected error importing xpriv with %s", tc.name)
			}
		})
	}
}

// Public keys that are not on the curve must be rejected on import.
func TestImportRejectsOffCurvePubKey(t *testing.T) {
	for _, curve := range []Curve{NewSecp256k1(), NewNist256p1()} {
		node, err := NewMasterNode(testSeed(t), curve)
		if err != nil {
			t.Fatalf("%s: %v", curve.Name(), err)
		}
		forged := node.Neuter()
		forged.PubKey = make([]byte, 33)
		forged.PubKey[0] = 0x02
		for i := 1; i < 33; i++ {
			forged.PubKey[i] = 0xFF // x coordinate above the field prime
		}
		if _, err := NewNodeFromExtendedKey(forged.XPub(), curve); err == nil {
			t.Errorf("%s: expected error importing off-curve public key", curve.Name())
		}
	}
}

// Extended keys with unrecognized version bytes must be rejected.
func TestImportRejectsUnknownVersion(t *testing.T) {
	curve := NewSecp256k1()
	node, err := NewMasterNode(testSeed(t), curve)
	if err != nil {
		t.Fatal(err)
	}
	forged := *node
	forged.IsPrivate = false // force serialize() through XPub with bogus version
	forged.Version = []byte{0x01, 0x02, 0x03, 0x04}
	key := forged.serialize(forged.Version, forged.PubKey)
	_, err = NewNodeFromExtendedKey(key, curve)
	if err == nil {
		t.Fatal("expected error for unknown version bytes")
	}
	if !strings.Contains(err.Error(), "unknown extended key version") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Seed length must be 16 to 64 bytes per SLIP-10.
func TestNewMasterNodeSeedLength(t *testing.T) {
	curve := NewSecp256k1()
	for _, n := range []int{0, 4, 15, 65, 128} {
		if _, err := NewMasterNode(make([]byte, n), curve); err == nil {
			t.Errorf("expected error for %d-byte seed", n)
		}
	}
	for _, n := range []int{16, 32, 64} {
		if _, err := NewMasterNode(make([]byte, n), curve); err != nil {
			t.Errorf("unexpected error for %d-byte seed: %v", n, err)
		}
	}
}

// Base58 extended keys make no sense for ed25519-bip32 (64-byte keys).
func TestBase58RejectedForEd25519Bip32(t *testing.T) {
	secpNode, err := NewMasterNode(testSeed(t), NewSecp256k1())
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewNodeFromExtendedKey(secpNode.XPriv(), NewEd25519Bip32())
	if err == nil {
		t.Error("expected error importing base58 key with ed25519-bip32 curve")
	}
}

// CIP-5 human-readable prefixes (root_xsk, root_xvk, ...) must be accepted on import.
func TestBech32CIP5HrpImport(t *testing.T) {
	curve := NewEd25519Bip32()
	node, err := NewMasterNode(testSeed(t), curve)
	if err != nil {
		t.Fatal(err)
	}

	privPayload := make([]byte, 96)
	copy(privPayload[:64], node.PrivKey)
	copy(privPayload[64:], node.ChainCode)
	privData, _ := bech32.ConvertBits(privPayload, 8, 5, true)
	rootXsk, err := bech32.Encode("root_xsk", privData)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := NewNodeFromExtendedKey(rootXsk, curve)
	if err != nil {
		t.Fatalf("failed to import root_xsk: %v", err)
	}
	if !bytes.Equal(imported.PrivKey, node.PrivKey) || !bytes.Equal(imported.ChainCode, node.ChainCode) {
		t.Error("root_xsk import does not match original node")
	}

	pubPayload := make([]byte, 64)
	copy(pubPayload[:32], node.PubKey[1:])
	copy(pubPayload[32:], node.ChainCode)
	pubData, _ := bech32.ConvertBits(pubPayload, 8, 5, true)
	rootXvk, err := bech32.Encode("root_xvk", pubData)
	if err != nil {
		t.Fatal(err)
	}
	importedPub, err := NewNodeFromExtendedKey(rootXvk, curve)
	if err != nil {
		t.Fatalf("failed to import root_xvk: %v", err)
	}
	if importedPub.IsPrivate || !bytes.Equal(importedPub.PubKey, node.PubKey) {
		t.Error("root_xvk import does not match original node")
	}
}

// Bech32 import must reject private keys that cannot come from valid derivation
// and public keys that do not decode to a curve point.
func TestBech32ImportValidation(t *testing.T) {
	curve := NewEd25519Bip32()
	node, err := NewMasterNode(testSeed(t), curve)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unclamped kL", func(t *testing.T) {
		payload := make([]byte, 96)
		copy(payload[:64], node.PrivKey)
		copy(payload[64:], node.ChainCode)
		payload[0] |= 0x01 // kL no longer a multiple of 8
		data, _ := bech32.ConvertBits(payload, 8, 5, true)
		encoded, _ := bech32.Encode("xprv", data)
		if _, err := NewNodeFromExtendedKey(encoded, curve); err == nil {
			t.Error("expected error for kL that is not a multiple of 8")
		}
	})

	t.Run("invalid point", func(t *testing.T) {
		// Roughly half of all y coordinates have no matching x on the curve;
		// scan for one instead of hardcoding it.
		invalid := make([]byte, 32)
		for b := 0; b < 256; b++ {
			invalid[0] = byte(b)
			if !validEd25519Point(invalid) {
				break
			}
		}
		if validEd25519Point(invalid) {
			t.Fatal("could not find an invalid point encoding")
		}

		payload := make([]byte, 64)
		copy(payload[:32], invalid)
		copy(payload[32:], node.ChainCode)
		data, _ := bech32.ConvertBits(payload, 8, 5, true)
		encoded, _ := bech32.Encode("xpub", data)
		if _, err := NewNodeFromExtendedKey(encoded, curve); err == nil {
			t.Error("expected error for public key that is not a valid point")
		}
	})
}

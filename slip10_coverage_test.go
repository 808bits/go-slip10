package slip10

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestEd25519Bip32PublicKeyInvalidLengths tests error handling for invalid key lengths
func TestEd25519Bip32PublicKeyInvalidLengths(t *testing.T) {
	curve := NewEd25519Bip32()

	tests := []struct {
		name    string
		privKey []byte
		wantNil bool
	}{
		{
			name:    "empty key",
			privKey: []byte{},
			wantNil: true,
		},
		{
			name:    "too short (31 bytes)",
			privKey: make([]byte, 31),
			wantNil: true,
		},
		{
			name:    "invalid length (33 bytes)",
			privKey: make([]byte, 33),
			wantNil: true,
		},
		{
			name:    "invalid length (63 bytes)",
			privKey: make([]byte, 63),
			wantNil: true,
		},
		{
			name:    "invalid length (65 bytes)",
			privKey: make([]byte, 65),
			wantNil: true,
		},
		{
			name:    "valid 32 bytes",
			privKey: make([]byte, 32),
			wantNil: false,
		},
		{
			name:    "valid 64 bytes",
			privKey: make([]byte, 64),
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := curve.PublicKey(tt.privKey)
			if tt.wantNil && result != nil {
				t.Errorf("PublicKey() expected nil for invalid length, got %d bytes", len(result))
			}
			if !tt.wantNil && result == nil {
				t.Errorf("PublicKey() expected non-nil for valid length, got nil")
			}
		})
	}
}

// TestEd25519Bip32DerivePublicChildErrors tests error paths in DerivePublicChild
func TestEd25519Bip32DerivePublicChildErrors(t *testing.T) {
	curve := NewEd25519Bip32()

	// Create a valid master node for testing
	seed := make([]byte, 32)
	seed[0] = 0x01
	node, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("Failed to create master node: %v", err)
	}

	tests := []struct {
		name      string
		pubKey    []byte
		chainCode []byte
		index     uint32
		wantErr   string
	}{
		{
			name:      "hardened derivation from public key",
			pubKey:    node.PubKey,
			chainCode: node.ChainCode,
			index:     HardenedOffset,
			wantErr:   "cannot derive hardened child from public key",
		},
		{
			name:      "invalid public key length (31 bytes)",
			pubKey:    make([]byte, 31),
			chainCode: node.ChainCode,
			index:     0,
			wantErr:   "invalid public key length",
		},
		{
			name:      "invalid public key length (34 bytes)",
			pubKey:    make([]byte, 34),
			chainCode: node.ChainCode,
			index:     0,
			wantErr:   "invalid public key length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := curve.DerivePublicChild(tt.pubKey, tt.chainCode, tt.index)
			if err == nil {
				t.Errorf("DerivePublicChild() expected error, got nil")
				return
			}
			if err.Error() != tt.wantErr {
				t.Errorf("DerivePublicChild() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestEd25519Bip32DerivePrivateChildInvalidKey tests error when private key is wrong size
func TestEd25519Bip32DerivePrivateChildInvalidKey(t *testing.T) {
	curve := NewEd25519Bip32()
	chainCode := make([]byte, 32)

	tests := []struct {
		name    string
		privKey []byte
	}{
		{"32 bytes (should be 64)", make([]byte, 32)},
		{"65 bytes (too long)", make([]byte, 65)},
		{"empty", []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := curve.DerivePrivateChild(tt.privKey, chainCode, 0)
			if err == nil {
				t.Error("DerivePrivateChild() expected error for invalid key length, got nil")
			}
		})
	}
}

// TestEd25519Bip32PublicChildDerivation validates public child derivation matches private derivation
func TestEd25519Bip32PublicChildDerivation(t *testing.T) {
	curve := NewEd25519Bip32()

	// Create a master node
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	node, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("Failed to create master node: %v", err)
	}

	// Derive a child using private derivation
	childPriv, err := node.Derive(0) // soft derivation
	if err != nil {
		t.Fatalf("Failed to derive child from private: %v", err)
	}

	// Derive the same child using public derivation
	neuteredNode := node.Neuter()
	childPub, err := neuteredNode.Derive(0) // public derivation
	if err != nil {
		t.Fatalf("Failed to derive child from public: %v", err)
	}

	// Public keys should match
	if !bytes.Equal(childPriv.PubKey, childPub.PubKey) {
		t.Errorf("Public keys don't match:\n  private derivation: %x\n  public derivation:  %x",
			childPriv.PubKey, childPub.PubKey)
	}

	// Chain codes should match
	if !bytes.Equal(childPriv.ChainCode, childPub.ChainCode) {
		t.Errorf("Chain codes don't match:\n  private derivation: %x\n  public derivation:  %x",
			childPriv.ChainCode, childPub.ChainCode)
	}
}

// TestEd25519Bip32DerivePublicChildWithRawKey tests derivation with 32-byte raw public key
func TestEd25519Bip32DerivePublicChildWithRawKey(t *testing.T) {
	curve := NewEd25519Bip32()

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	node, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("Failed to create master node: %v", err)
	}

	// Get raw 32-byte public key (without 0x00 prefix)
	rawPubKey := node.PubKey[1:] // Remove prefix

	// Should be able to derive with raw 32-byte key
	childPub, childChain, err := curve.DerivePublicChild(rawPubKey, node.ChainCode, 0)
	if err != nil {
		t.Fatalf("DerivePublicChild with raw key failed: %v", err)
	}

	if len(childPub) != 33 {
		t.Errorf("Expected 33-byte public key, got %d bytes", len(childPub))
	}

	if len(childChain) != 32 {
		t.Errorf("Expected 32-byte chain code, got %d bytes", len(childChain))
	}
}

// TestXPrivXPubPublicOnlyNode tests XPriv/XPub behavior for public-only nodes
func TestXPrivXPubPublicOnlyNode(t *testing.T) {
	curve := NewSecp256k1()

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	node, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("Failed to create master node: %v", err)
	}

	// Neuter the node
	pubNode := node.Neuter()

	// XPriv should return empty string for public-only node
	if xpriv := pubNode.XPriv(); xpriv != "" {
		t.Errorf("XPriv() on public-only node should return empty string, got %s", xpriv)
	}

	// XPub should work for public-only node
	xpub := pubNode.XPub()
	if xpub == "" {
		t.Error("XPub() on public-only node should not return empty string")
	}

	// Should be able to parse it back
	restored, err := NewNodeFromExtendedKey(xpub, curve)
	if err != nil {
		t.Fatalf("Failed to parse xpub: %v", err)
	}

	if restored.IsPrivate {
		t.Error("Restored node should be public-only")
	}

	if !bytes.Equal(restored.PubKey, pubNode.PubKey) {
		t.Error("Restored public key doesn't match")
	}
}

// TestNeuterAlreadyPublic tests that Neuter returns nil for public-only nodes
func TestNeuterAlreadyPublic(t *testing.T) {
	curve := NewSecp256k1()

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	node, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("Failed to create master node: %v", err)
	}

	pubNode := node.Neuter()
	if pubNode == nil {
		t.Fatal("First Neuter() should not return nil")
	}

	// Second Neuter should return nil
	result := pubNode.Neuter()
	if result != nil {
		t.Error("Neuter() on already-public node should return nil")
	}
}

// TestExtendedPrivKeyPublicOnly tests ExtendedPrivKey returns nil for public nodes
func TestExtendedPrivKeyPublicOnly(t *testing.T) {
	curve := NewSecp256k1()

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	node, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("Failed to create master node: %v", err)
	}

	pubNode := node.Neuter()
	if pubNode.ExtendedPrivKey() != nil {
		t.Error("ExtendedPrivKey() on public-only node should return nil")
	}
}

// TestSecp256k1PublicChildDerivation tests public child derivation for secp256k1
func TestSecp256k1PublicChildDerivation(t *testing.T) {
	curve := NewSecp256k1()

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	node, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("Failed to create master node: %v", err)
	}

	// Derive child 0 from private key
	childPriv, err := node.Derive(0)
	if err != nil {
		t.Fatalf("Private derivation failed: %v", err)
	}

	// Derive child 0 from public key
	pubNode := node.Neuter()
	childPub, err := pubNode.Derive(0)
	if err != nil {
		t.Fatalf("Public derivation failed: %v", err)
	}

	// Public keys should match
	if !bytes.Equal(childPriv.PubKey, childPub.PubKey) {
		t.Error("Public keys from private and public derivation don't match")
	}
}

// TestNist256p1PublicChildDerivation tests public child derivation for NIST P-256
func TestNist256p1PublicChildDerivation(t *testing.T) {
	curve := NewNist256p1()

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	node, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("Failed to create master node: %v", err)
	}

	// Derive child 0 from private key
	childPriv, err := node.Derive(0)
	if err != nil {
		t.Fatalf("Private derivation failed: %v", err)
	}

	// Derive child 0 from public key
	pubNode := node.Neuter()
	childPub, err := pubNode.Derive(0)
	if err != nil {
		t.Fatalf("Public derivation failed: %v", err)
	}

	// Public keys should match
	if !bytes.Equal(childPriv.PubKey, childPub.PubKey) {
		t.Error("Public keys from private and public derivation don't match")
	}
}

// TestWeierstrassPublicChildHardened tests that hardened public derivation fails
func TestWeierstrassPublicChildHardened(t *testing.T) {
	curves := []struct {
		name  string
		curve Curve
	}{
		{"secp256k1", NewSecp256k1()},
		{"nist256p1", NewNist256p1()},
	}

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			node, err := NewMasterNode(seed, tc.curve)
			if err != nil {
				t.Fatalf("Failed to create master node: %v", err)
			}

			pubNode := node.Neuter()
			_, err = pubNode.Derive(HardenedOffset)
			if err == nil {
				t.Error("Hardened derivation from public key should fail")
			}
		})
	}
}

// TestNodeStringMethod tests the String() method with edge cases
func TestNodeStringMethod(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	node, _ := NewMasterNode(seed, curve)

	str := node.String()
	if str == "" {
		t.Error("String() should not return empty string")
	}

	// Should contain curve name
	if !bytes.Contains([]byte(str), []byte("secp256k1")) {
		t.Error("String() should contain curve name")
	}

	// Test with nil curve
	nilCurveNode := &Node{Depth: 0, IsPrivate: true}
	str = nilCurveNode.String()
	if str == "" {
		t.Error("String() with nil curve should not return empty string")
	}
}

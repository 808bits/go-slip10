package slip10

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestNewNodeFromExtendedKeyEdgeCases tests additional error paths when parsing extended keys
func TestNewNodeFromExtendedKeyEdgeCases(t *testing.T) {
	curve := NewSecp256k1()
	cardanoCurve := NewEd25519Bip32()

	// Create a valid xpriv for testing manipulations
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	node, _ := NewMasterNode(seed, curve)
	validXpriv := node.XPriv()

	tests := []struct {
		name    string
		key     string
		curve   Curve
		wantErr string
	}{
		{
			name:    "invalid encoding",
			key:     "not-a-valid-key",
			curve:   curve,
			wantErr: "invalid extended key encoding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewNodeFromExtendedKey(tt.key, tt.curve)
			if err == nil {
				t.Errorf("NewNodeFromExtendedKey() expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewNodeFromExtendedKey() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}

	// Test that valid xpriv can be parsed
	_, err := NewNodeFromExtendedKey(validXpriv, curve)
	if err != nil {
		t.Errorf("Failed to parse valid xpriv: %v", err)
	}

	// Test Cardano bech32 xpriv round-trip
	cardanoNode, _ := NewMasterNode(seed, cardanoCurve)
	cardanoXpriv := cardanoNode.XPriv()
	restored, err := NewNodeFromExtendedKey(cardanoXpriv, cardanoCurve)
	if err != nil {
		t.Fatalf("Failed to parse Cardano xpriv: %v", err)
	}
	if !restored.IsPrivate {
		t.Error("Restored Cardano node should be private")
	}

	// Test Cardano bech32 xpub round-trip
	cardanoXpub := cardanoNode.XPub()
	restoredPub, err := NewNodeFromExtendedKey(cardanoXpub, cardanoCurve)
	if err != nil {
		t.Fatalf("Failed to parse Cardano xpub: %v", err)
	}
	if restoredPub.IsPrivate {
		t.Error("Restored Cardano public node should not be private")
	}

	// Test bech32 with wrong curve - use a real Cardano xpriv with secp256k1 curve
	_, err = NewNodeFromExtendedKey(cardanoXpriv, curve)
	if err == nil {
		t.Error("Parsing Cardano bech32 with secp256k1 curve should fail")
	} else if !strings.Contains(err.Error(), "bech32 encoding is only supported for ed25519-bip32") {
		t.Errorf("Expected ed25519-bip32 error, got: %v", err)
	}
}

// TestParsePathErrors tests error paths in ParsePath
func TestParsePathErrors(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{
			name:    "doesn't start with m/",
			path:    "44'/0'/0'",
			wantErr: "path must start with 'm/'",
		},
		{
			name:    "empty segment",
			path:    "m/44'//0'",
			wantErr: "empty segment",
		},
		{
			name:    "invalid index",
			path:    "m/abc",
			wantErr: "invalid path part",
		},
		{
			name:    "index too large",
			path:    "m/2147483648", // HardenedOffset
			wantErr: "index too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePath(tt.path)
			if err == nil {
				t.Errorf("ParsePath() expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ParsePath() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}

	// Test valid paths
	validPaths := []struct {
		path      string
		wantLen   int
		wantFirst uint32
	}{
		{"m", 0, 0},
		{"", 0, 0},
		{"m/0", 1, 0},
		{"m/44'", 1, HardenedOffset + 44},
		{"m/44h", 1, HardenedOffset + 44},
		{"m/44H", 1, HardenedOffset + 44},
		{"m/44'/0'/0'", 3, HardenedOffset + 44},
	}

	for _, tt := range validPaths {
		t.Run("valid_"+tt.path, func(t *testing.T) {
			indices, err := ParsePath(tt.path)
			if err != nil {
				t.Errorf("ParsePath(%q) unexpected error: %v", tt.path, err)
				return
			}
			if len(indices) != tt.wantLen {
				t.Errorf("ParsePath(%q) returned %d indices, want %d", tt.path, len(indices), tt.wantLen)
			}
			if tt.wantLen > 0 && indices[0] != tt.wantFirst {
				t.Errorf("ParsePath(%q) first index = %d, want %d", tt.path, indices[0], tt.wantFirst)
			}
		})
	}
}

// TestDerivePathError tests error handling in DerivePath
func TestDerivePathError(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	node, _ := NewMasterNode(seed, curve)

	// Invalid path should fail
	_, err := node.DerivePath("invalid/path")
	if err == nil {
		t.Error("DerivePath with invalid path should fail")
	}

	// Valid path should work
	child, err := node.DerivePath("m/44'/0'/0'")
	if err != nil {
		t.Errorf("DerivePath with valid path failed: %v", err)
	}
	if child.Depth != 3 {
		t.Errorf("Expected depth 3, got %d", child.Depth)
	}
}

// TestXPubTestnet tests XPub with testnet version
func TestXPubTestnet(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	node, _ := NewMasterNode(seed, curve)

	// Set testnet version
	node.Version = VersionTestPrivate
	xpriv := node.XPriv()
	if !strings.HasPrefix(xpriv, "tprv") {
		t.Errorf("XPriv with testnet version should start with 'tprv', got %s", xpriv[:4])
	}

	// Neuter should produce testnet xpub
	pubNode := node.Neuter()
	xpub := pubNode.XPub()
	if !strings.HasPrefix(xpub, "tpub") {
		t.Errorf("XPub with testnet version should start with 'tpub', got %s", xpub[:4])
	}
}

// TestXPubWith32BytePubKey tests XPub with 32-byte Ed25519-BIP32 public key
func TestXPubWith32BytePubKey(t *testing.T) {
	curve := NewEd25519Bip32()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	node, _ := NewMasterNode(seed, curve)

	// Manipulate to have 32-byte public key (without prefix)
	nodeCopy := *node
	nodeCopy.PubKey = node.PubKey[1:] // Remove 0x00 prefix

	xpub := nodeCopy.XPub()
	if xpub == "" {
		t.Error("XPub should work with 32-byte public key")
	}
}

// TestEd25519BaseClassPublicDerivation tests that base ed25519 doesn't support public derivation
func TestEd25519BaseClassPublicDerivation(t *testing.T) {
	curve := NewEd25519()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	node, _ := NewMasterNode(seed, curve)

	// Neuter the node
	pubNode := node.Neuter()

	// Public derivation should fail
	_, err := pubNode.Derive(0)
	if err == nil {
		t.Error("Public derivation on ed25519 should fail")
	}
}

// TestCurve25519PublicDerivation tests that curve25519 doesn't support public derivation
func TestCurve25519PublicDerivation(t *testing.T) {
	curve := NewCurve25519()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	node, _ := NewMasterNode(seed, curve)

	// Neuter the node
	pubNode := node.Neuter()

	// Public derivation should fail
	_, err := pubNode.Derive(0)
	if err == nil {
		t.Error("Public derivation on curve25519 should fail")
	}
}

// TestWipe tests that Wipe clears sensitive data
func TestWipe(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	node, _ := NewMasterNode(seed, curve)

	// Verify we have data before wipe
	hasNonZero := false
	for _, b := range node.PrivKey {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Fatal("PrivKey should have non-zero bytes before wipe")
	}

	// Wipe and check
	node.Wipe()

	for _, b := range node.PrivKey {
		if b != 0 {
			t.Error("PrivKey should be all zeros after Wipe")
			break
		}
	}

	for _, b := range node.ChainCode {
		if b != 0 {
			t.Error("ChainCode should be all zeros after Wipe")
			break
		}
	}
}

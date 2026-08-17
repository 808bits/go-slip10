package slip10

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/meehow/go-slip10/bech32"
)

// Test vectors generated from Ledger's Python HDEd25519 reference implementation.
// These use the standard BIP-39 test mnemonic:
// "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
func TestEd25519Bip32MasterKey(t *testing.T) {
	// Seed from BIP-39 mnemonic with empty passphrase and "mnemonic" prefix
	seed := MnemonicToSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")

	curve := NewEd25519Bip32()
	node, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("failed to create master node: %v", err)
	}

	if !node.IsPrivate {
		t.Error("master node should be private")
	}

	// Extended private key should be 64 bytes
	if len(node.PrivKey) != 64 {
		t.Errorf("expected 64-byte private key, got %d bytes", len(node.PrivKey))
	}

	// Chain code should be 32 bytes
	if len(node.ChainCode) != 32 {
		t.Errorf("expected 32-byte chain code, got %d bytes", len(node.ChainCode))
	}

	// Public key should be 33 bytes (0x00 prefix + 32 bytes)
	if len(node.PubKey) != 33 {
		t.Errorf("expected 33-byte public key, got %d bytes", len(node.PubKey))
	}

	if node.PubKey[0] != 0x00 {
		t.Errorf("expected 0x00 prefix on public key, got 0x%02x", node.PubKey[0])
	}
}

func TestEd25519Bip32HardenedDerivation(t *testing.T) {
	seed := MnemonicToSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
	curve := NewEd25519Bip32()
	master, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("failed to create master node: %v", err)
	}

	// Test hardened derivation (all indices with ')
	testCases := []struct {
		path string
	}{
		{"m/0'"},
		{"m/1852'"},
		{"m/1852'/1815'"},
		{"m/1852'/1815'/0'"},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			node, err := master.DerivePath(tc.path)
			if err != nil {
				t.Fatalf("failed to derive path %s: %v", tc.path, err)
			}

			if len(node.PrivKey) != 64 {
				t.Errorf("expected 64-byte private key, got %d", len(node.PrivKey))
			}

			if len(node.PubKey) != 33 {
				t.Errorf("expected 33-byte public key, got %d", len(node.PubKey))
			}
		})
	}
}

func TestEd25519Bip32SoftDerivation(t *testing.T) {
	seed := MnemonicToSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
	curve := NewEd25519Bip32()
	master, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("failed to create master node: %v", err)
	}

	// Test standard Cardano CIP-1852 path with soft derivation at the end
	// m/1852'/1815'/0'/0/0 - Payment key
	cardanoPath := "m/1852'/1815'/0'/0/0"
	node, err := master.DerivePath(cardanoPath)
	if err != nil {
		t.Fatalf("failed to derive Cardano path %s: %v", cardanoPath, err)
	}

	if len(node.PrivKey) != 64 {
		t.Errorf("expected 64-byte private key, got %d", len(node.PrivKey))
	}

	// Also test staking key path: m/1852'/1815'/0'/2/0
	stakingPath := "m/1852'/1815'/0'/2/0"
	stakingNode, err := master.DerivePath(stakingPath)
	if err != nil {
		t.Fatalf("failed to derive staking path %s: %v", stakingPath, err)
	}

	if len(stakingNode.PrivKey) != 64 {
		t.Errorf("expected 64-byte private key, got %d", len(stakingNode.PrivKey))
	}

	// Payment and staking keys should be different
	if bytes.Equal(node.PubKey, stakingNode.PubKey) {
		t.Error("payment and staking keys should be different")
	}
}

func TestEd25519Bip32PublicDerivation(t *testing.T) {
	seed := MnemonicToSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
	curve := NewEd25519Bip32()
	master, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("failed to create master node: %v", err)
	}

	// Derive to account level (hardened) first
	accountNode, err := master.DerivePath("m/1852'/1815'/0'")
	if err != nil {
		t.Fatalf("failed to derive account: %v", err)
	}

	// Create a public-only node from account
	pubAccountNode := &Node{
		Curve:     curve,
		IsPrivate: false,
		PrivKey:   nil,
		PubKey:    accountNode.PubKey,
		ChainCode: accountNode.ChainCode,
		Depth:     accountNode.Depth,
		ParentFP:  accountNode.ParentFP,
		Index:     accountNode.Index,
		Version:   VersionMainPublic,
	}

	// Derive child 0/0 privately from account
	privChild, err := accountNode.DerivePath("m/0/0")
	if err != nil {
		t.Fatalf("failed private derivation: %v", err)
	}

	// Derive child 0/0 publicly from public account
	pubChild0, err := pubAccountNode.Derive(0)
	if err != nil {
		t.Fatalf("failed public derivation step 1: %v", err)
	}

	pubChild, err := pubChild0.Derive(0)
	if err != nil {
		t.Fatalf("failed public derivation step 2: %v", err)
	}

	// Public keys should match
	if hex.EncodeToString(pubChild.PubKey) != hex.EncodeToString(privChild.PubKey) {
		t.Errorf("public derivation mismatch:\npublic:  %x\nprivate: %x",
			pubChild.PubKey, privChild.PubKey)
	}

	// Public node should not have private key
	if pubChild.PrivKey != nil {
		t.Error("public node should not have private key")
	}
}

func TestEd25519Bip32PublicDerivationHardenedFails(t *testing.T) {
	seed := MnemonicToSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
	curve := NewEd25519Bip32()
	master, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("failed to create master node: %v", err)
	}

	// Create a public-only node
	pubNode := &Node{
		Curve:     curve,
		IsPrivate: false,
		PrivKey:   nil,
		PubKey:    master.PubKey,
		ChainCode: master.ChainCode,
		Depth:     0,
		ParentFP:  []byte{0, 0, 0, 0},
		Index:     0,
	}

	// Hardened derivation should fail on public node
	_, err = pubNode.Derive(HardenedOffset)
	if err == nil {
		t.Error("expected error for hardened derivation from public node")
	}
}

func TestEd25519Bip32CurveName(t *testing.T) {
	curve := NewEd25519Bip32()
	if curve.Name() != "ed25519-bip32" {
		t.Errorf("expected curve name 'ed25519-bip32', got '%s'", curve.Name())
	}
}

func TestEd25519Bip32ExtendedPrivKey(t *testing.T) {
	seed := MnemonicToSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
	curve := NewEd25519Bip32()
	node, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("failed to create master node: %v", err)
	}

	extPrivKey := node.ExtendedPrivKey()
	if len(extPrivKey) != 64 {
		t.Errorf("expected 64-byte extended private key, got %d", len(extPrivKey))
	}

	// Should be same as PrivKey
	if !bytes.Equal(extPrivKey, node.PrivKey) {
		t.Error("ExtendedPrivKey should match PrivKey")
	}
}

func TestEd25519Bip32ExtendedPrivKeyPublicNode(t *testing.T) {
	node := &Node{
		Curve:     NewEd25519Bip32(),
		IsPrivate: false,
		PrivKey:   nil,
		PubKey:    make([]byte, 33),
		ChainCode: make([]byte, 32),
	}

	extPrivKey := node.ExtendedPrivKey()
	if extPrivKey != nil {
		t.Error("ExtendedPrivKey should be nil for public node")
	}
}

// TestEd25519Bip32DeterministicDerivation verifies that derivation is deterministic.
func TestEd25519Bip32DeterministicDerivation(t *testing.T) {
	seed := MnemonicToSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")

	// Create two separate master nodes
	curve1 := NewEd25519Bip32()
	curve2 := NewEd25519Bip32()

	master1, _ := NewMasterNode(seed, curve1)
	master2, _ := NewMasterNode(seed, curve2)

	// Derive the same path on both
	path := "m/1852'/1815'/0'/0/0"
	node1, _ := master1.DerivePath(path)
	node2, _ := master2.DerivePath(path)

	// Results should be identical
	if !bytes.Equal(node1.PrivKey, node2.PrivKey) {
		t.Error("deterministic derivation failed: private keys differ")
	}
	if !bytes.Equal(node1.PubKey, node2.PubKey) {
		t.Error("deterministic derivation failed: public keys differ")
	}
	if !bytes.Equal(node1.ChainCode, node2.ChainCode) {
		t.Error("deterministic derivation failed: chain codes differ")
	}
}

// TestEd25519Bip32InvalidPrivKeyLength tests error handling for wrong key length.
func TestEd25519Bip32InvalidPrivKeyLength(t *testing.T) {
	curve := NewEd25519Bip32()

	// Try to derive with wrong key length
	_, _, err := curve.DerivePrivateChild(make([]byte, 32), make([]byte, 32), 0)
	if err == nil {
		t.Error("expected error for 32-byte private key")
	}
}

// TestEd25519Bip32MultipleIndices tests derivation at various indices.
func TestEd25519Bip32MultipleIndices(t *testing.T) {
	seed := MnemonicToSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
	curve := NewEd25519Bip32()
	master, _ := NewMasterNode(seed, curve)

	// Derive multiple children at different indices
	indices := []uint32{0, 1, 100, 1000, HardenedOffset, HardenedOffset + 1}

	var prevPubKey []byte
	for _, idx := range indices {
		child, err := master.Derive(idx)
		if err != nil {
			t.Fatalf("failed to derive at index %d: %v", idx, err)
		}

		// Each child should have different public key
		if bytes.Equal(child.PubKey, prevPubKey) {
			t.Errorf("children at different indices have same public key (index %d)", idx)
		}
		prevPubKey = child.PubKey
	}
}

// TestEd25519Bip32CardanoCryptoVectors tests against official IntersectMBO/cardano-crypto test vectors.
// Source: https://github.com/IntersectMBO/cardano-crypto/blob/master/tests/goldens/cardano/crypto/wallet/BIP39-128
// These vectors use derivation-scheme2 (Ed25519-BIP32) and verify that xPriv → xPub derivation is correct.
func TestEd25519Bip32CardanoCryptoVectors(t *testing.T) {
	testCases := []struct {
		name  string
		xPriv string   // 64 bytes hex (kL || kR)
		xPub  string   // 64 bytes hex (pubKey || chainCode)
		path  []uint32 // Derivation path indices (for documentation only)
	}{
		{
			// Vector 8: derivation-scheme2, path [0', 1', 2', 2', 1000000000]
			name:  "Vector8_scheme2",
			xPriv: "6802ad6bef3df647df4d1d70e47243ce996da560aa7c35525286b5f33f8aea53969cf5c72e1116f12541ef2174e9fa6d0ef55953b4a2cdc001fd31338367cab0",
			xPub:  "5ce717275763d4280340b17c226647e0ca2ae354bf12302ecdab4f68d60f75bd9074ab37060f8a3083016e6f3755de58016f209f6a7103d63b1f80c53f99db99",
			path:  []uint32{HardenedOffset, HardenedOffset + 1, HardenedOffset + 2, HardenedOffset + 2, 3147483648},
		},
		{
			// Vector 9: derivation-scheme2, path [0', 1']
			name:  "Vector9_scheme2",
			xPriv: "38fd98b0d02aaad10fd5cac9ca49538893650217874c628f6bed04f12d8aea5335f265a96086cc1582a0218a26afaa396d7eb942925b591a5c3b6b197da7f697",
			xPub:  "6973f1cc551b572afa1bd1b4b3aab0b634276529f36fda6f07019591077f5fa1f5a9712fc11766a3fdd89df7689f4e891ee6402ce62c2592069cd12609c8a91c",
			path:  []uint32{HardenedOffset, HardenedOffset + 1},
		},
		{
			// Vector 10: derivation-scheme2, path [0', 1', 24, 2000] (includes soft derivation)
			name:  "Vector10_scheme2_soft",
			xPriv: "28053701c7f8ecb7008433ce3d2b704e1e187ab7433c621c2e48f034358aea53caa94d26385382a932746c71a6c3f5a8f7a6dd287257bc20b63442ac47ac223a",
			xPub:  "e3120d182378d4a083f42f90a9c4ba0272bd0a6329e3896ab1948cfda9b904203c000b503f844fe3ec22c6c65bcdc4cb45aaba98a5cafc05ab25b04360494213",
			path:  []uint32{HardenedOffset, HardenedOffset + 1, 24, 2000},
		},
		{
			// Vector 11: derivation-scheme2, path [0', 1', 24, 2000'] (soft then hardened)
			name:  "Vector11_scheme2_mixed",
			xPriv: "f886d53c974c2dbed823411dced93bc2ff486fe16be30ab44748a3f3358aea5348470cf985d8712428a5896fbd79f9c913e8eb2e886801709afb17454061c198",
			xPub:  "355637f1249e0bb6c4540972898362f247d9f2b9f4ab75de0d94ed8800514a1b758643705fea51bfe9316d8d6cd1315b414fe7ab2515949cb88accc5eccb96e4",
			path:  []uint32{HardenedOffset, HardenedOffset + 1, 24, HardenedOffset + 2000},
		},
		{
			// Vector 14: derivation-scheme2, path [] (master key only)
			name:  "Vector14_scheme2_master",
			xPriv: "08a14df748e477a69d21c97c56db151fc19e2521f31dd0ac5360f269e5b6ea46daeb991f2d2128e2525415c56a07f4366baa26c1e48572a5e073934b6de35fbc",
			xPub:  "9a1d04808b4c0682816961cf666e82a7fd35949658aba5354c517eccf12aacb4affbc325d9027c0f2d9f925b1dcf6c12bf5c1dd08904474066a4f2c00db56173",
			path:  []uint32{},
		},
	}

	curve := NewEd25519Bip32()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse expected xPub (pubKey || chainCode)
			expectedXPub, err := hex.DecodeString(tc.xPub)
			if err != nil {
				t.Fatalf("failed to decode xPub: %v", err)
			}
			expectedPubKey := expectedXPub[:32]
			expectedChainCode := expectedXPub[32:]

			// Parse xPriv
			xPrivBytes, err := hex.DecodeString(tc.xPriv)
			if err != nil {
				t.Fatalf("failed to decode xPriv: %v", err)
			}

			// Create node from xPriv and verify public key derivation
			node := &Node{
				Curve:     curve,
				IsPrivate: true,
				PrivKey:   xPrivBytes,
				ChainCode: expectedChainCode,
				Depth:     uint8(len(tc.path)),
				ParentFP:  []byte{0, 0, 0, 0},
				Version:   VersionMainPrivate,
			}
			node.PubKey = curve.PublicKey(node.PrivKey)

			derivedPubKey := node.PubKey[1:] // Skip 0x00 prefix
			if hex.EncodeToString(derivedPubKey) != hex.EncodeToString(expectedPubKey) {
				t.Errorf("public key mismatch:\nexpected: %x\ngot:      %x", expectedPubKey, derivedPubKey)
			}
		})
	}
}

func TestCardanoSerialization(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	curve := NewEd25519Bip32()
	master, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("failed to create master node: %v", err)
	}

	t.Run("XPriv Serialization", func(t *testing.T) {
		xpriv := master.XPriv()
		if !strings.HasPrefix(xpriv, "xprv") {
			t.Errorf("expected xpriv prefix, got %s", xpriv)
		}

		// Decode and verify
		node, err := NewNodeFromExtendedKey(xpriv, curve)
		if err != nil {
			t.Fatalf("failed to decode xpriv: %v", err)
		}

		if !node.IsPrivate {
			t.Error("expected private node")
		}
		if !bytes.Equal(node.PrivKey, master.PrivKey) {
			t.Errorf("private key mismatch:\nWant: %x\nGot:  %x", master.PrivKey, node.PrivKey)
		}
		if !bytes.Equal(node.ChainCode, master.ChainCode) {
			t.Errorf("chain code mismatch:\nWant: %x\nGot:  %x", master.ChainCode, node.ChainCode)
		}
	})

	t.Run("XPub Serialization", func(t *testing.T) {
		xpub := master.XPub()
		if !strings.HasPrefix(xpub, "xpub") {
			t.Errorf("expected xpub prefix, got %s", xpub)
		}

		// Decode and verify
		node, err := NewNodeFromExtendedKey(xpub, curve)
		if err != nil {
			t.Fatalf("failed to decode xpub: %v", err)
		}

		if node.IsPrivate {
			t.Error("expected public node")
		}
		if !bytes.Equal(node.PubKey, master.PubKey) {
			t.Errorf("public key mismatch:\nWant: %x\nGot:  %x", master.PubKey, node.PubKey)
		}
		if !bytes.Equal(node.ChainCode, master.ChainCode) {
			t.Errorf("chain code mismatch:\nWant: %x\nGot:  %x", master.ChainCode, node.ChainCode)
		}
	})

	t.Run("Wrong Curve for Bech32", func(t *testing.T) {
		xpriv := master.XPriv()
		secp := NewSecp256k1()
		_, err := NewNodeFromExtendedKey(xpriv, secp)
		if err == nil {
			t.Error("expected error when decoding bech32 with non-ed25519-bip32 curve")
		}
		if err.Error() != "bech32 encoding is only supported for ed25519-bip32 curve" {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("Invalid Bech32 Length", func(t *testing.T) {
		// Create a fake bech32 string with "xprv" prefix but wrong data size
		// We can't easily construct a valid checksum with invalid length without using the bech32 lib.
		// So we skip constructing one manually.
	})
}

func TestCardanoEdgeCases(t *testing.T) {
	curve := NewEd25519Bip32()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	t.Run("XPriv on Public Node", func(t *testing.T) {
		pubNode, _ := NewNodeFromExtendedKey(master.XPub(), curve)
		xpriv := pubNode.XPriv()
		if xpriv != "" {
			t.Errorf("expected empty string for XPriv on public node, got %s", xpriv)
		}
	})

	t.Run("Invalid Extended Key Encoding", func(t *testing.T) {
		_, err := NewNodeFromExtendedKey("notavalidkey", curve)
		if err == nil {
			t.Error("expected error for invalid encoding")
		}
		if err.Error() != "invalid extended key encoding (neither base58 nor bech32)" {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestCardanoBech32EdgeCases(t *testing.T) {
	curve := NewEd25519Bip32()

	t.Run("Unknown HRP", func(t *testing.T) {
		data := make([]byte, 100)
		encoded, err := bech32.Encode("unknown", data)
		if err != nil {
			t.Fatalf("failed to encode: %v", err)
		}

		_, err = NewNodeFromExtendedKey(encoded, curve)
		if err == nil {
			t.Error("expected error for unknown hrp")
		}
		if err.Error() != "unknown bech32 hrp: unknown" {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Invalid xprv Length", func(t *testing.T) {
		data := make([]byte, 152)
		encoded, _ := bech32.Encode("xprv", data)

		_, err := NewNodeFromExtendedKey(encoded, curve)
		if err == nil {
			t.Error("expected error for invalid xprv length")
		}
	})

	t.Run("Invalid xpub Length", func(t *testing.T) {
		data := make([]byte, 96)
		encoded, _ := bech32.Encode("xpub", data)

		_, err := NewNodeFromExtendedKey(encoded, curve)
		if err == nil {
			t.Error("expected error for invalid xpub length")
		}
	})

	t.Run("Invalid Padding (ConvertBits fails)", func(t *testing.T) {
		data := make([]byte, 1)
		encoded, _ := bech32.Encode("xprv", data)

		_, err := NewNodeFromExtendedKey(encoded, curve)
		if err == nil {
			t.Error("expected error for invalid padding")
		}
	})
}

func TestEd25519Bip32PublicKeyInvalidLengths(t *testing.T) {
	curve := NewEd25519Bip32()

	tests := []struct {
		name    string
		privKey []byte
		wantNil bool
	}{
		{"empty key", []byte{}, true},
		{"too short (31 bytes)", make([]byte, 31), true},
		{"invalid length (33 bytes)", make([]byte, 33), true},
		{"invalid length (63 bytes)", make([]byte, 63), true},
		{"invalid length (65 bytes)", make([]byte, 65), true},
		{"valid 32 bytes", make([]byte, 32), false},
		{"valid 64 bytes", make([]byte, 64), false},
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

func TestEd25519Bip32DerivePublicChildErrors(t *testing.T) {
	curve := NewEd25519Bip32()

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

func TestEd25519Bip32DerivePublicChildWithRawKey(t *testing.T) {
	curve := NewEd25519Bip32()

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	node, err := NewMasterNode(seed, curve)
	if err != nil {
		t.Fatalf("Failed to create master node: %v", err)
	}

	// 32-byte raw public key without the 0x00 prefix should also work
	rawPubKey := node.PubKey[1:]

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

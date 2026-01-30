package slip10

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"

	"github.com/meehow/go-slip10/base58"
	"github.com/meehow/go-slip10/bech32"
	"golang.org/x/crypto/ripemd160" //lint:ignore SA1019 Required by BIP-32 spec for fingerprinting
)

const (
	// HardenedOffset is added to child index to indicate hardened derivation (BIP-32).
	// Indices >= HardenedOffset are hardened; indices < HardenedOffset are normal.
	HardenedOffset = 0x80000000
)

var (
	// VersionMainPublic is the BIP-32 version bytes for mainnet extended public keys (xpub).
	VersionMainPublic = []byte{0x04, 0x88, 0xB2, 0x1E}
	// VersionMainPrivate is the BIP-32 version bytes for mainnet extended private keys (xpriv).
	VersionMainPrivate = []byte{0x04, 0x88, 0xAD, 0xE4}
	// VersionTestPublic is the BIP-32 version bytes for testnet extended public keys (tpub).
	VersionTestPublic = []byte{0x04, 0x35, 0x87, 0xCF}
	// VersionTestPrivate is the BIP-32 version bytes for testnet extended private keys (tpriv).
	VersionTestPrivate = []byte{0x04, 0x35, 0x83, 0x94}

	zeroFingerprint = []byte{0, 0, 0, 0}
)

const (
	// Data lengths
	versionLen   = 4
	depthLen     = 1
	parentFPLen  = 4
	indexLen     = 4
	chainCodeLen = 32
	keyLen       = 33
	totalLen     = versionLen + depthLen + parentFPLen + indexLen + chainCodeLen + keyLen // 78

	// Offsets
	versionOffset   = 0
	depthOffset     = versionOffset + versionLen
	parentFPOffset  = depthOffset + depthLen
	indexOffset     = parentFPOffset + parentFPLen
	chainCodeOffset = indexOffset + indexLen
	keyOffset       = chainCodeOffset + chainCodeLen
)

// Node represents an extended key in the SLIP-10 hierarchy.
type Node struct {
	Curve     Curve
	IsPrivate bool
	PrivKey   []byte
	PubKey    []byte
	ChainCode []byte
	Depth     byte
	ParentFP  []byte
	Index     uint32
	Version   []byte
}

// NewMasterNode creates a new master node from a seed for the specified curve.
func NewMasterNode(seed []byte, curve Curve) (*Node, error) {
	privKey, chainCode, err := curve.MasterKey(seed)
	if err != nil {
		return nil, err
	}

	return &Node{
		Curve:     curve,
		IsPrivate: true,
		PrivKey:   privKey,
		PubKey:    curve.PublicKey(privKey),
		ChainCode: chainCode,
		Depth:     0,
		ParentFP:  zeroFingerprint,
		Index:     0,
		Version:   VersionMainPrivate,
	}, nil
}

func isPrivateVersion(version []byte) bool {
	return bytes.Equal(version, VersionMainPrivate) || bytes.Equal(version, VersionTestPrivate)
}

func parseKeyData(actualKeyData []byte, isPrivate bool, curve Curve) (privKey, pubKey []byte, err error) {
	if isPrivate {
		if actualKeyData[0] != 0 {
			return nil, nil, errors.New("invalid private key prefix")
		}
		privKey = actualKeyData[1:]
		if len(privKey) != 32 {
			return nil, nil, errors.New("invalid private key length")
		}
		pubKey = curve.PublicKey(privKey)
	} else {
		pubKey = actualKeyData
		if len(pubKey) != 33 {
			return nil, nil, errors.New("invalid public key length")
		}
		if pubKey[0] != 0x02 && pubKey[0] != 0x03 {
			return nil, nil, errors.New("invalid public key prefix")
		}
	}
	return privKey, pubKey, nil
}

func validateNodeFields(depth byte, index uint32, parentFP []byte) error {
	if depth == 0 {
		if index != 0 {
			return errors.New("index must be 0 for depth 0")
		}
		for _, b := range parentFP {
			if b != 0 {
				return errors.New("parent fingerprint must be 0 for depth 0")
			}
		}
	}
	return nil
}

// NewNodeFromExtendedKey creates a node from serialized extended key (xpub/xpriv).
func NewNodeFromExtendedKey(extendedKey string, curve Curve) (*Node, error) {
	// Try Base58Check first (standard SLIP-10/BIP-32)
	payload, err := base58.CheckDecode(extendedKey)
	if err == nil {
		if len(payload) != totalLen {
			return nil, errors.New("invalid extended key length")
		}

		version := payload[versionOffset:depthOffset]
		depth := payload[depthOffset]
		parentFP := payload[parentFPOffset:indexOffset]
		index := uint32(payload[indexOffset])<<24 | uint32(payload[indexOffset+1])<<16 | uint32(payload[indexOffset+2])<<8 | uint32(payload[indexOffset+3])
		chainCode := payload[chainCodeOffset:keyOffset]
		actualKeyData := payload[keyOffset:]

		isPrivate := isPrivateVersion(version)
		privKey, pubKey, err := parseKeyData(actualKeyData, isPrivate, curve)
		if err != nil {
			return nil, err
		}

		if err := validateNodeFields(depth, index, parentFP); err != nil {
			return nil, err
		}

		return &Node{
			Curve:     curve,
			IsPrivate: isPrivate,
			PrivKey:   privKey,
			PubKey:    pubKey,
			ChainCode: chainCode,
			Depth:     depth,
			ParentFP:  parentFP,
			Index:     index,
			Version:   version,
		}, nil
	}

	// Try Bech32 (Cardano / Ed25519-BIP32)
	hrp, data, err := bech32.Decode(extendedKey)
	if err == nil {
		if curve.Name() != "ed25519-bip32" {
			return nil, errors.New("bech32 encoding is only supported for ed25519-bip32 curve")
		}

		// Convert 5-bit groups back to 8-bit bytes
		payload, err := bech32.ConvertBits(data, 5, 8, false)
		if err != nil {
			return nil, fmt.Errorf("failed to convert bech32 bits: %v", err)
		}

		var isPrivate bool
		var privKey, pubKey, chainCode []byte

		if hrp == "xprv" {
			// Cardano xprv payload: 96 bytes (64 bytes key + 32 bytes chain code)
			if len(payload) != 96 {
				return nil, fmt.Errorf("invalid bech32 xval length for xprv: expected 96, got %d", len(payload))
			}
			isPrivate = true
			privKey = payload[:64]
			chainCode = payload[64:]
			pubKey = curve.PublicKey(privKey)
		} else if hrp == "xpub" {
			// Cardano xpub payload: 64 bytes (32 bytes public key + 32 bytes chain code)
			if len(payload) != 64 {
				return nil, fmt.Errorf("invalid bech32 xval length for xpub: expected 64, got %d", len(payload))
			}
			isPrivate = false
			rawPubKey := payload[:32]
			chainCode = payload[32:]

			// Add 0x00 prefix for internal format
			pubKey = make([]byte, 33)
			pubKey[0] = 0x00
			copy(pubKey[1:], rawPubKey)
		} else {
			return nil, fmt.Errorf("unknown bech32 hrp: %s", hrp)
		}

		return &Node{
			Curve:     curve,
			IsPrivate: isPrivate,
			PrivKey:   privKey,
			PubKey:    pubKey,
			ChainCode: chainCode,
			Depth:     0,               // Cardano Bech32 doesn't encode depth
			ParentFP:  zeroFingerprint, // Cardano Bech32 doesn't encode parent FP
			Index:     0,               // Cardano Bech32 doesn't encode index
			Version:   nil,
		}, nil
	}

	return nil, errors.New("invalid extended key encoding (neither base58 nor bech32)")
}

// Derive derives a child node at the given index.
func (n *Node) Derive(index uint32) (*Node, error) {
	if !n.IsPrivate && index >= HardenedOffset {
		return nil, errors.New("cannot derive hardened child from public parent")
	}

	if n.IsPrivate {
		childPriv, childChain, err := n.Curve.DerivePrivateChild(n.PrivKey, n.ChainCode, index)
		if err != nil {
			return nil, err
		}

		return &Node{
			Curve:     n.Curve,
			IsPrivate: true,
			PrivKey:   childPriv,
			PubKey:    n.Curve.PublicKey(childPriv),
			ChainCode: childChain,
			Depth:     n.Depth + 1,
			ParentFP:  n.Fingerprint(),
			Index:     index,
			Version:   n.Version,
		}, nil
	}

	// Public child derivation (CKDpub)
	childPub, childChain, err := n.Curve.DerivePublicChild(n.PubKey, n.ChainCode, index)
	if err != nil {
		return nil, err
	}

	return &Node{
		Curve:     n.Curve,
		IsPrivate: false,
		PrivKey:   nil,
		PubKey:    childPub,
		ChainCode: childChain,
		Depth:     n.Depth + 1,
		ParentFP:  n.Fingerprint(),
		Index:     index,
		Version:   n.Version,
	}, nil
}

// DerivePath derives a child node following the given path (e.g., "m/44'/0'/0'/0/0").
func (n *Node) DerivePath(path string) (*Node, error) {
	indices, err := ParsePath(path)
	if err != nil {
		return nil, err
	}

	curr := n
	for _, index := range indices {
		curr, err = curr.Derive(index)
		if err != nil {
			return nil, err
		}
	}

	return curr, nil
}

// ParsePath parses a BIP-32 path string into a slice of uint32 indices.
// The path must start with "m". Use "/" as separator.
// Example: "m/44'/0'/0'" -> [2147483692, 2147483648, 2147483648]
func ParsePath(path string) ([]uint32, error) {
	if path == "m" || path == "" {
		return nil, nil
	}

	if len(path) < 2 || path[0] != 'm' || path[1] != '/' {
		return nil, errors.New("path must start with 'm/'")
	}

	// Count slashes to pre-allocate
	count := 0
	for i := 2; i < len(path); i++ {
		if path[i] == '/' {
			count++
		}
	}
	count++ // last segment

	indices := make([]uint32, 0, count)
	start := 2
	for i := 2; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			if start == i {
				return nil, fmt.Errorf("invalid path part %q: empty segment", "")
			}
			index, err := parseIndex(path[start:i])
			if err != nil {
				return nil, fmt.Errorf("invalid path part %q: %v", path[start:i], err)
			}
			indices = append(indices, index)
			start = i + 1
		}
	}

	return indices, nil
}

// Wipe overwrites the private key and chain code with zeros to protect sensitive data in memory.
// It is recommended to call this method when the Node is no longer needed.
func (n *Node) Wipe() {
	clear(n.PrivKey)
	clear(n.ChainCode)
}

// serialize writes the node data to a 78-byte buffer and returns the Base58Check encoding.
func (n *Node) serialize(version []byte, keyData []byte) string {
	var data [totalLen]byte
	copy(data[versionOffset:], version)
	data[depthOffset] = n.Depth
	copy(data[parentFPOffset:], n.ParentFP)
	data[indexOffset] = byte(n.Index >> 24)
	data[indexOffset+1] = byte(n.Index >> 16)
	data[indexOffset+2] = byte(n.Index >> 8)
	data[indexOffset+3] = byte(n.Index)
	copy(data[chainCodeOffset:], n.ChainCode)
	copy(data[keyOffset:], keyData)

	return base58.CheckEncode(data[:])
}

// XPriv returns the extended private key (xpriv) string.
func (n *Node) XPriv() string {
	if !n.IsPrivate {
		return ""
	}

	// Cardano (Ed25519-BIP32) Special Case: Use Bech32
	if n.Curve.Name() == "ed25519-bip32" {
		// Payload: 64 bytes key + 32 bytes chain code = 96 bytes
		payload := make([]byte, 96)
		copy(payload[:64], n.PrivKey)
		copy(payload[64:], n.ChainCode)

		// Convert to 5-bit groups
		data, err := bech32.ConvertBits(payload, 8, 5, true)
		if err != nil {
			return "" // Should not happen
		}

		encoded, err := bech32.Encode("xprv", data)
		if err != nil {
			return ""
		}
		return encoded
	}

	version := VersionMainPrivate // Default
	if n.Version != nil {         // n.Version is slice, len check not strictly needed if we trust constructor, but nil check is good
		version = n.Version
	}

	// Private key data is 0x00 + 32 bytes key
	var keyData [keyLen]byte
	keyData[0] = 0x00
	copy(keyData[1:], n.PrivKey)

	return n.serialize(version, keyData[:])
}

// XPub returns the extended public key (xpub) string.
func (n *Node) XPub() string {
	// Cardano (Ed25519-BIP32) Special Case: Use Bech32
	if n.Curve.Name() == "ed25519-bip32" {
		// Payload: 32 bytes public key (no prefix) + 32 bytes chain code = 64 bytes
		payload := make([]byte, 64)

		// Remove 0x00 prefix if present (it should be for Ed25519-BIP32)
		if len(n.PubKey) == 33 {
			copy(payload[:32], n.PubKey[1:])
		} else {
			copy(payload[:32], n.PubKey)
		}
		copy(payload[32:], n.ChainCode)

		// Convert to 5-bit groups
		data, err := bech32.ConvertBits(payload, 8, 5, true)
		if err != nil {
			return ""
		}

		encoded, err := bech32.Encode("xpub", data)
		if err != nil {
			return ""
		}
		return encoded
	}

	version := VersionMainPublic
	if n.Version != nil && n.Version[0] == 0x04 && n.Version[1] == 0x35 {
		version = VersionTestPublic
	}

	return n.serialize(version, n.PubKey)
}

// Fingerprint returns the fingerprint of the node's public key.
func (n *Node) Fingerprint() []byte {
	sha := sha256.Sum256(n.PubKey)
	h := ripemd160.New()
	h.Write(sha[:])
	hash := h.Sum(nil)
	return hash[:4]
}

// Neuter returns a new public-only node derived from this node.
// The returned node cannot be used for private key operations.
// Returns nil if the node is already public-only.
func (n *Node) Neuter() *Node {
	if !n.IsPrivate {
		return nil
	}

	version := VersionMainPublic
	if bytes.Equal(n.Version, VersionTestPrivate) {
		version = VersionTestPublic
	}

	return &Node{
		Curve:     n.Curve,
		IsPrivate: false,
		PrivKey:   nil,
		PubKey:    n.PubKey,
		ChainCode: n.ChainCode,
		Depth:     n.Depth,
		ParentFP:  n.ParentFP,
		Index:     n.Index,
		Version:   version,
	}
}

// PublicKey returns the public key associated with this node.
func (n *Node) PublicKey() []byte {
	return n.PubKey
}

// ExtendedPrivKey returns the full private key for curves with extended keys.
// For Ed25519-BIP32, this returns the 64-byte extended key (kL || kR).
// For other curves, this returns the same as PrivKey.
// Returns nil for public-only nodes.
func (n *Node) ExtendedPrivKey() []byte {
	if !n.IsPrivate {
		return nil
	}
	return n.PrivKey
}

func parseIndex(s string) (uint32, error) {
	if len(s) == 0 {
		return 0, errors.New("empty index")
	}

	var hardened bool
	last := s[len(s)-1]
	if last == '\'' || last == 'h' || last == 'H' {
		hardened = true
		s = s[:len(s)-1]
	}

	idx, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}

	if idx >= HardenedOffset {
		return 0, errors.New("index too large")
	}

	if hardened {
		return uint32(idx) + HardenedOffset, nil
	}
	return uint32(idx), nil
}

// String returns a safe string representation of the node (does not expose private key).
func (n *Node) String() string {
	curveName := ""
	if n.Curve != nil {
		curveName = n.Curve.Name()
	}
	return fmt.Sprintf("Node{curve=%s, depth=%d, private=%t}", curveName, n.Depth, n.IsPrivate)
}

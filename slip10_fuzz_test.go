package slip10

import (
	"testing"
)

// FuzzParsePath fuzzes parsing of BIP-32 paths.
func FuzzParsePath(f *testing.F) {
	f.Add("m/0/1/2")
	f.Add("m/44'/0'/0'")
	f.Add("")
	f.Add("m//")
	f.Add("invalid")

	f.Fuzz(func(t *testing.T, path string) {
		_, _ = ParsePath(path)
	})
}

// FuzzNewNodeFromExtendedKey fuzzes parsing of xpub/xpriv keys.
func FuzzNewNodeFromExtendedKey(f *testing.F) {
	seeds := []string{
		"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		"xpriv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKm2sEWEYgnHXYJJKR29zpVpUfXgy22qHRDxuz7L8CslS",
		"",
		"invalid",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, key string) {
		for _, curve := range []Curve{NewSecp256k1(), NewNist256p1(), NewEd25519(), NewCurve25519()} {
			_, _ = NewNodeFromExtendedKey(key, curve)
		}
	})
}

// FuzzMasterNode fuzzes master node creation with random seeds.
func FuzzMasterNode(f *testing.F) {
	f.Add([]byte("seed"))
	f.Add([]byte(""))
	f.Add([]byte("0123456789abcdef"))

	f.Fuzz(func(t *testing.T, seed []byte) {
		for _, curve := range []Curve{NewSecp256k1(), NewNist256p1(), NewEd25519(), NewCurve25519()} {
			_, _ = NewMasterNode(seed, curve)
		}
	})
}

// FuzzDerive fuzzes single-step derivation.
func FuzzDerive(f *testing.F) {
	f.Add([]byte("0123456789abcdef"), uint32(0))
	f.Add([]byte("0123456789abcdef"), uint32(0x80000000))

	f.Fuzz(func(t *testing.T, seed []byte, index uint32) {
		for _, curve := range []Curve{NewSecp256k1(), NewNist256p1(), NewEd25519(), NewCurve25519()} {
			master, err := NewMasterNode(seed, curve)
			if err != nil {
				continue
			}
			// Test private derivation
			child, err := master.Derive(index)
			if err == nil && child != nil {
				// If worked, try to derive from child too
				_, _ = child.Derive(index)
			}

			// Test public derivation if applicable
			if !master.IsPrivate {
				_, _ = master.Derive(index)
			} else {
				// Convert to public and try derivation
				xpub := master.XPub()
				publicNode, err := NewNodeFromExtendedKey(xpub, curve)
				if err == nil {
					_, _ = publicNode.Derive(index)
				}
			}
		}
	})
}

// FuzzDerivePath fuzzes path-based derivation.
func FuzzDerivePath(f *testing.F) {
	f.Add([]byte("0123456789abcdef"), "m/0/1")
	f.Add([]byte("0123456789abcdef"), "m/44'/0'/0'")

	f.Fuzz(func(t *testing.T, seed []byte, path string) {
		for _, curve := range []Curve{NewSecp256k1(), NewNist256p1(), NewEd25519(), NewCurve25519()} {
			master, err := NewMasterNode(seed, curve)
			if err != nil {
				continue
			}
			_, _ = master.DerivePath(path)
		}
	})
}

package slip10_test

import (
	"encoding/hex"
	"fmt"

	"github.com/meehow/go-slip10"
)

func ExampleMnemonicToSeed() {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "TREZOR"

	seed := slip10.MnemonicToSeed(mnemonic, passphrase)
	fmt.Printf("%x\n", seed)
	// Output: c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
}

func ExampleNewMasterNode() {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, err := slip10.NewMasterNode(seed, slip10.NewSecp256k1())
	if err != nil {
		panic(err)
	}

	fmt.Println(master.XPub())
	// Output: xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8
}

func ExampleNode_DerivePath() {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := slip10.NewMasterNode(seed, slip10.NewSecp256k1())

	// Derive BIP-44 Bitcoin path: m/44'/0'/0'/0/0
	child, err := master.DerivePath("m/44'/0'/0'/0/0")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%x\n", child.PublicKey())
	// Output: 0239b4b3a27cd1dd8993038d5eb6449220b350c32ae62fec0833b93db8a49031c5
}

func ExampleNode_Neuter() {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := slip10.NewMasterNode(seed, slip10.NewSecp256k1())

	// Neuter the master node to create a public-only version
	publicMaster := master.Neuter()

	// The neutered node can still derive public children
	child, _ := publicMaster.Derive(0)

	fmt.Printf("Public key: %x\n", child.PublicKey())
	fmt.Printf("Private key is nil: %v\n", child.PrivKey == nil)
	// Output:
	// Public key: 027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c
	// Private key is nil: true
}

func ExampleNewNodeFromExtendedKey() {
	xpub := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

	node, err := slip10.NewNodeFromExtendedKey(xpub, slip10.NewSecp256k1())
	if err != nil {
		panic(err)
	}

	// This is a public node - can only derive non-hardened children
	child, _ := node.Derive(0)
	fmt.Printf("%x\n", child.PublicKey())
	// Output: 027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c
}

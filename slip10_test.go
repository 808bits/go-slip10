package slip10

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/meehow/go-slip10/base58"
)

func TestNeuter(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	t.Run("Mainnet", func(t *testing.T) {
		master, _ := NewMasterNode(seed, NewSecp256k1())
		neutered := master.Neuter()

		if neutered == nil {
			t.Fatal("Neuter returned nil")
		}
		if neutered.IsPrivate {
			t.Error("Neutered node should not be private")
		}
		if neutered.PrivKey != nil {
			t.Error("Neutered node should have nil PrivKey")
		}
		if !bytes.Equal(neutered.PubKey, master.PubKey) {
			t.Error("Public keys should match")
		}
		if !bytes.Equal(neutered.Version, VersionMainPublic) {
			t.Errorf("Expected mainnet public version, got %x", neutered.Version)
		}

		// Derived public key should match
		childPriv, _ := master.Derive(0)
		childPub, _ := neutered.Derive(0)
		if !bytes.Equal(childPub.PubKey, childPriv.PubKey) {
			t.Error("Derived public keys should match")
		}
	})

	t.Run("Testnet", func(t *testing.T) {
		master, _ := NewMasterNode(seed, NewSecp256k1())
		master.Version = VersionTestPrivate
		neutered := master.Neuter()

		if !bytes.Equal(neutered.Version, VersionTestPublic) {
			t.Errorf("Expected testnet public version, got %x", neutered.Version)
		}
	})

	t.Run("Already public", func(t *testing.T) {
		master, _ := NewMasterNode(seed, NewSecp256k1())
		neutered := master.Neuter()
		doubleNeutered := neutered.Neuter()

		if doubleNeutered != nil {
			t.Error("Neuter on public node should return nil")
		}
	})
}

type slipTestCase struct {
	path              string
	parentFingerprint string
	chainCode         string
	privKey           string
	pubKey            string
}

func TestSlip10PythonVectors(t *testing.T) {
	seed1 := "000102030405060708090a0b0c0d0e0f"
	seed2 := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

	vectors := []struct {
		name      string
		seed      string
		curveName string
		nodes     []slipTestCase
	}{
		{
			name:      "Vector 1 secp256k1",
			seed:      seed1,
			curveName: "secp256k1",
			nodes: []slipTestCase{
				{"m", "00000000", "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508", "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35", "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"},
				{"m/0h", "3442193e", "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141", "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea", "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"},
				{"m/0h/1", "5c1bd648", "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19", "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368", "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"},
				{"m/0h/1/2h", "bef5a2f9", "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f", "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca", "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"},
				{"m/0h/1/2h/2", "ee7ab90c", "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd", "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4", "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"},
				{"m/0h/1/2h/2/1000000000", "d880d7d8", "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e", "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8", "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"},
			},
		},
		{
			name:      "Vector 1 nist256p1",
			seed:      seed1,
			curveName: "nist256p1",
			nodes: []slipTestCase{
				{"m", "00000000", "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea", "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2", "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8"},
				{"m/0h", "be6105b5", "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11", "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c", "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c"},
				{"m/0h/1", "9b02312f", "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c", "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129", "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844"},
				{"m/0h/1/2h", "b98005c1", "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318", "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7", "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0"},
				{"m/0h/1/2h/2", "0e9f3274", "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0", "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa", "029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20"},
				{"m/0h/1/2h/2/1000000000", "8b2b5c4b", "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059", "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119", "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4"},
			},
		},
		{
			name:      "Vector 1 ed25519",
			seed:      seed1,
			curveName: "ed25519",
			nodes: []slipTestCase{
				{"m", "00000000", "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"},
				{"m/0h", "ddebc675", "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69", "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"},
				{"m/0h/1h", "13dab143", "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14", "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2", "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"},
				{"m/0h/1h/2h", "ebe4cb29", "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c", "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9", "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"},
				{"m/0h/1h/2h/2h", "316ec1c6", "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc", "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662", "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"},
				{"m/0h/1h/2h/2h/1000000000h", "d6322ccd", "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230", "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793", "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"},
			},
		},
		{
			name:      "Vector 1 curve25519",
			seed:      seed1,
			curveName: "curve25519",
			nodes: []slipTestCase{
				{"m", "00000000", "77997ca3588a1a34f3589279ea2962247abfe5277d52770a44c706378c710768", "d70a59c2e68b836cc4bbe8bcae425169b9e2384f3905091e3d60b890e90cd92c", "005c7289dc9f7f3ea1c8c2de7323b9fb0781f69c9ecd6de4f095ac89a02dc80577"},
				{"m/0h", "6f5a9c0d", "349a3973aad771c628bf1f1b4d5e071f18eff2e492e4aa7972a7e43895d6597f", "cd7630d7513cbe80515f7317cdb9a47ad4a56b63c3f1dc29583ab8d4cc25a9b2", "00cb8be6b256ce509008b43ae0dccd69960ad4f7ff2e2868c1fbc9e19ec3ad544b"},
				{"m/0h/1h", "fde474d7", "2ee5ba14faf2fe9d7ab532451c2be3a0a5375c5e8c44fb31d9ad7edc25cda000", "a95f97cfc1a61dd833b882c89d36a78a030ea6b2fbe3ae2a70e4f1fc9008d6b1", "00e9506455dce2526df42e5e4eb5585eaef712e5f9c6a28bf9fb175d96595ea872"},
				{"m/0h/1h/2h", "6569dde7", "e1897d5a96459ce2a3d294cb2a6a59050ee61255818c50e03ac4263ef17af084", "3d6cce04a9175929da907a90b02176077b9ae050dcef9b959fed978bb2200cdc", "0018f008fcbc6d1cd8b4fe7a9eba00f6570a9da02a9b0005028cb2731b12ee4118"},
				{"m/0h/1h/2h/2h", "1b7cce71", "1cccc84e2737cfe81b51fbe4c97bbdb000f6a76eddffb9ed03108fbff3ff7e4f", "7ae7437efe0a3018999e6f00d72e810ebc50578dbf6728bfa1c7fe73501081a7", "00512e288a8ef4d869620dc4b06bb06ad2524b350dee5a39fcfeb708dbac65c25c"},
				{"m/0h/1h/2h/2h/1000000000h", "de5dcb65", "8ccf15d55b1dda246b0c1bf3e979a471a82524c1bd0c1eaecccf00dde72168bb", "7a59954d387abde3bc703f531f67d659ec2b8a12597ae82824547d7e27991e26", "00a077fcf5af53d210257d44a86eb2031233ac7237da220434ac01a0bebccc1919"},
			},
		},
		{
			name:      "Vector 2 secp256k1",
			seed:      seed2,
			curveName: "secp256k1",
			nodes: []slipTestCase{
				{"m", "00000000", "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689", "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e", "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"},
				{"m/0", "bd16bee5", "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c", "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e", "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"},
				{"m/0/2147483647h", "5a61ff8e", "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9", "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93", "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"},
				{"m/0/2147483647h/1", "d8ab4937", "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb", "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7", "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"},
				{"m/0/2147483647h/1/2147483646h", "78412e3a", "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29", "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d", "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"},
				{"m/0/2147483647h/1/2147483646h/2", "31a507b8", "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271", "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23", "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"},
			},
		},
		{
			name:      "Retry secp256r1",
			seed:      seed1,
			curveName: "nist256p1",
			nodes: []slipTestCase{
				{"m/28578h", "be6105b5", "e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2", "06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669", "02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7"},
				{"m/28578h/33941", "3e2b7bc6", "9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071", "092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a", "0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120"},
			},
		},
		{
			name:      "Seed retry secp256r1",
			seed:      "a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446",
			curveName: "nist256p1",
			nodes: []slipTestCase{
				{"m", "00000000", "7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c", "3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f", "0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20"},
			},
		},
	}

	curves := map[string]Curve{
		"secp256k1":  NewSecp256k1(),
		"nist256p1":  NewNist256p1(),
		"ed25519":    NewEd25519(),
		"curve25519": NewCurve25519(),
	}

	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			curve := curves[tt.curveName]
			seed, _ := hex.DecodeString(tt.seed)
			master, err := NewMasterNode(seed, curve)
			if err != nil {
				t.Fatalf("failed to create master node: %v", err)
			}

			for _, tc := range tt.nodes {
				node, err := master.DerivePath(tc.path)
				if err != nil {
					t.Fatalf("failed to derive path %s: %v", tc.path, err)
				}

				if hex.EncodeToString(node.ParentFP) != tc.parentFingerprint {
					t.Errorf("path %s: expected parent fingerprint %s, got %s", tc.path, tc.parentFingerprint, hex.EncodeToString(node.ParentFP))
				}
				if hex.EncodeToString(node.ChainCode) != tc.chainCode {
					t.Errorf("path %s: expected chain code %s, got %s", tc.path, tc.chainCode, hex.EncodeToString(node.ChainCode))
				}
				if hex.EncodeToString(node.PrivKey) != tc.privKey {
					t.Errorf("path %s: expected privKey %s, got %s", tc.path, tc.privKey, hex.EncodeToString(node.PrivKey))
				}
				if hex.EncodeToString(node.PublicKey()) != tc.pubKey {
					t.Errorf("path %s: expected pubKey %s, got %s", tc.path, tc.pubKey, hex.EncodeToString(node.PublicKey()))
				}
			}
		})
	}
}

func TestBip32Vectors(t *testing.T) {
	curve := NewSecp256k1()
	seed1, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	t.Run("Vector 1", func(t *testing.T) {
		master, _ := NewMasterNode(seed1, curve)

		expectedXPub := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
		expectedXPriv := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

		if master.XPub() != expectedXPub {
			t.Errorf("expected xpub %s, got %s", expectedXPub, master.XPub())
		}
		if master.XPriv() != expectedXPriv {
			t.Errorf("expected xpriv %s, got %s", expectedXPriv, master.XPriv())
		}

		// m/0H
		node, _ := master.DerivePath("m/0H")
		expectedXPub = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
		expectedXPriv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
		if node.XPub() != expectedXPub {
			t.Errorf("m/0H: expected xpub %s, got %s", expectedXPub, node.XPub())
		}
		if node.XPriv() != expectedXPriv {
			t.Errorf("m/0H: expected xpriv %s, got %s", expectedXPriv, node.XPriv())
		}
	})

	t.Run("Invalid keys", func(t *testing.T) {
		invalidXPubs := []string{
			"xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
			"xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
		}
		for _, xpub := range invalidXPubs {
			_, err := NewNodeFromExtendedKey(xpub, curve)
			if err == nil {
				t.Errorf("expected error for invalid xpub %s", xpub)
			}
		}
	})
}

func TestBip39MnemonicToSeed(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "TREZOR"
	expectedSeed := "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"

	seed := MnemonicToSeed(mnemonic, passphrase)
	if hex.EncodeToString(seed) != expectedSeed {
		t.Errorf("expected seed %s, got %s", expectedSeed, hex.EncodeToString(seed))
	}
}

func TestCrossCheckSeedXPriv(t *testing.T) {
	seed, _ := hex.DecodeString("1077a46dc8545d372f22d9e110ae6c5c2bf7620fe9c4c911f5404d112233e1aa270567dd3554092e051ba3ba86c303590b0309116ac89964ff284db2219d7511")
	curve := NewSecp256k1()

	node1, _ := NewMasterNode(seed, curve)
	xpriv := node1.XPriv()

	node2, err := NewNodeFromExtendedKey(xpriv, curve)
	if err != nil {
		t.Fatalf("failed to create node from xpriv: %v", err)
	}

	if node1.XPub() != node2.XPub() {
		t.Errorf("xpub mismatch")
	}
}

func TestPublicDerivation(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed := MnemonicToSeed(mnemonic, "TREZOR")

	// Master Node (Private)
	master, _ := NewMasterNode(seed, NewSecp256k1())

	// Derive m/0 (Private)
	childPriv, _ := master.Derive(0)

	// Public Parent: m/0 public
	// Manually construct public node to simulate starting from xpub
	pubParent := &Node{
		Curve:     NewSecp256k1(),
		IsPrivate: false,
		PrivKey:   nil,
		PubKey:    childPriv.PubKey,
		ChainCode: childPriv.ChainCode,
		Depth:     childPriv.Depth,
		ParentFP:  childPriv.ParentFP,
		Index:     childPriv.Index,
		Version:   VersionMainPublic,
	}

	// Derive m/0/1 (Public) from Public Parent
	childPubFromPub, err := pubParent.Derive(1)
	if err != nil {
		t.Fatalf("public derivation failed: %v", err)
	}

	// Derive m/0/1 (Private) from Private Parent
	childPrivFromPriv, _ := childPriv.Derive(1)

	// Compare Public Keys
	if hex.EncodeToString(childPubFromPub.PubKey) != hex.EncodeToString(childPrivFromPriv.PubKey) {
		t.Errorf("public comparison failed: got %s, want %s", hex.EncodeToString(childPubFromPub.PubKey), hex.EncodeToString(childPrivFromPriv.PubKey))
	}
}

// Tests moved from coverage_test.go

// mockErrorCurve is a test curve that returns errors to test error paths
type mockErrorCurve struct {
	name          string
	masterKeyErr  error
	derivePrivErr error
	derivePubErr  error
}

func (c *mockErrorCurve) Name() string { return c.name }
func (c *mockErrorCurve) MasterKey(seed []byte) ([]byte, []byte, error) {
	if c.masterKeyErr != nil {
		return nil, nil, c.masterKeyErr
	}
	return make([]byte, 32), make([]byte, 32), nil
}
func (c *mockErrorCurve) DerivePrivateChild(privKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	if c.derivePrivErr != nil {
		return nil, nil, c.derivePrivErr
	}
	return make([]byte, 32), make([]byte, 32), nil
}
func (c *mockErrorCurve) DerivePublicChild(pubKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	if c.derivePubErr != nil {
		return nil, nil, c.derivePubErr
	}
	return make([]byte, 33), make([]byte, 32), nil
}
func (c *mockErrorCurve) PublicKey(privKey []byte) []byte {
	return make([]byte, 33)
}

// Test Ed25519 DerivePublicChild returns error (line 34-36 in curves.go)
func TestEd25519DerivePublicChildNotSupported(t *testing.T) {
	curve := NewEd25519()
	_, _, err := curve.DerivePublicChild(nil, nil, 0)
	if err == nil {
		t.Error("expected error for Ed25519 public child derivation")
	}
	if err.Error() != "public child derivation not supported for this curve" {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test Curve25519 DerivePublicChild returns error (inherits from baseCurve)
func TestCurve25519DerivePublicChildNotSupported(t *testing.T) {
	curve := NewCurve25519()
	_, _, err := curve.DerivePublicChild(nil, nil, 0)
	if err == nil {
		t.Error("expected error for Curve25519 public child derivation")
	}
	if err.Error() != "public child derivation not supported for this curve" {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test secp256k1 DerivePublicChild with invalid public key (line 63-64)
func TestSecp256k1DerivePublicChildInvalidKey(t *testing.T) {
	curve := NewSecp256k1()
	invalidPubKey := make([]byte, 33)
	invalidPubKey[0] = 0x02 // Correct prefix but invalid point
	for i := 1; i < 33; i++ {
		invalidPubKey[i] = 0xFF
	}
	chainCode := make([]byte, 32)

	_, _, err := curve.DerivePublicChild(invalidPubKey, chainCode, 0)
	if err == nil {
		t.Error("expected error for invalid public key")
	}
}

// Test deriveWeierstrassPublicChild with hardened index (line 115-117)
func TestWeierstrassPublicChildHardenedIndex(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Create a public-only node
	pubNode := &Node{
		Curve:     curve,
		IsPrivate: false,
		PubKey:    master.PubKey,
		ChainCode: master.ChainCode,
	}

	// Try hardened derivation
	_, err := pubNode.Derive(0x80000000)
	if err == nil {
		t.Error("expected error for hardened derivation from public key")
	}
	if !strings.Contains(err.Error(), "cannot derive hardened child from public") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test Ed25519 normal derivation error (line 184-186)
func TestEd25519NormalDerivationNotSupported(t *testing.T) {
	curve := NewEd25519()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Try normal (non-hardened) derivation - should fail
	_, err := master.Derive(0) // Normal index
	if err == nil {
		t.Error("expected error for normal derivation on Ed25519")
	}
	if !strings.Contains(err.Error(), "normal derivation not supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test Curve25519 normal derivation error (line 232-234)
func TestCurve25519NormalDerivationNotSupported(t *testing.T) {
	curve := NewCurve25519()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Try normal (non-hardened) derivation - should fail
	_, err := master.Derive(0) // Normal index
	if err == nil {
		t.Error("expected error for normal derivation on Curve25519")
	}
	if !strings.Contains(err.Error(), "normal derivation not supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test XPriv on public node returns empty string (line 286-288)
func TestXPrivOnPublicNode(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Create public node from XPub
	pubNode, _ := NewNodeFromExtendedKey(master.XPub(), curve)

	xpriv := pubNode.XPriv()
	if xpriv != "" {
		t.Errorf("expected empty string for XPriv on public node, got %s", xpriv)
	}
}

// Test XPriv with nil Version (line 290-292)
func TestXPrivWithNilVersion(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Set version to nil
	master.Version = nil
	xpriv := master.XPriv()

	// Should use default VersionMainPrivate
	if xpriv == "" {
		t.Error("expected non-empty XPriv")
	}

	// Decode and check version bytes
	decoded, _ := base58.CheckDecode(xpriv)
	expectedVersion := []byte{0x04, 0x88, 0xAD, 0xE4}
	if !bytes.Equal(decoded[:4], expectedVersion) {
		t.Errorf("expected version %x, got %x", expectedVersion, decoded[:4])
	}
}

// Test parseIndex with index too large (line 343-345)
func TestParseIndexTooLarge(t *testing.T) {
	// 2147483648 is HardenedOffset, which is >= HardenedOffset
	_, err := ParsePath("m/2147483648")
	if err == nil {
		t.Error("expected error for index too large")
	}
	if !strings.Contains(err.Error(), "index too large") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test parseIndex empty string error
func TestParseIndexEmpty(t *testing.T) {
	// This is caught by "empty segment" check first, but let's verify
	_, err := ParsePath("m//0")
	if err == nil {
		t.Error("expected error for empty segment")
	}
	if !strings.Contains(err.Error(), "empty segment") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test String() with nil Curve
func TestNodeStringNilCurve(t *testing.T) {
	node := &Node{
		Curve:     nil,
		IsPrivate: true,
		Depth:     0,
	}

	str := node.String()
	if str != "Node{curve=, depth=0, private=true}" {
		t.Errorf("unexpected String(): %s", str)
	}
}

// Test DerivePath error propagation (line 204-207)
func TestDerivePathErrorPropagation(t *testing.T) {
	curve := NewEd25519()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Ed25519 only supports hardened derivation, so m/0 should fail
	_, err := master.DerivePath("m/0")
	if err == nil {
		t.Error("expected error for normal derivation on Ed25519")
	}
	if !strings.Contains(err.Error(), "normal derivation not supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test Derive from public node with unsupported curve (tests public derivation error path)
func TestDerivePublicNodeUnsupportedCurve(t *testing.T) {
	curve := NewEd25519()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Create a public-only node (artificially)
	pubNode := &Node{
		Curve:     curve,
		IsPrivate: false,
		PubKey:    master.PubKey,
		ChainCode: master.ChainCode,
		Depth:     0,
		ParentFP:  []byte{0, 0, 0, 0},
		Index:     0,
	}

	// Try public derivation - should fail because Ed25519 doesn't support it
	_, err := pubNode.Derive(0)
	if err == nil {
		t.Error("expected error for public derivation on Ed25519")
	}
	if !strings.Contains(err.Error(), "public child derivation not supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test secp256k1 public derivation works correctly
func TestSecp256k1PublicDerivation(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Derive child privately
	childPriv, _ := master.Derive(0)

	// Create public-only parent
	pubParent := &Node{
		Curve:     curve,
		IsPrivate: false,
		PubKey:    master.PubKey,
		ChainCode: master.ChainCode,
		Depth:     0,
		ParentFP:  []byte{0, 0, 0, 0},
		Index:     0,
	}

	// Derive the same child publicly
	childPub, err := pubParent.Derive(0)
	if err != nil {
		t.Fatalf("public derivation failed: %v", err)
	}

	// Public keys should match
	if !bytes.Equal(childPub.PubKey, childPriv.PubKey) {
		t.Errorf("public keys don't match:\npub:  %x\npriv: %x", childPub.PubKey, childPriv.PubKey)
	}
}

// Test NewNodeFromExtendedKey with testnet xpriv
func TestNewNodeFromExtendedKeyTestnet(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Create testnet version
	master.Version = []byte{0x04, 0x35, 0x83, 0x94} // tprv

	// Export and reimport
	xpriv := master.XPriv()
	node, err := NewNodeFromExtendedKey(xpriv, curve)
	if err != nil {
		t.Fatalf("failed to parse testnet xpriv: %v", err)
	}

	if !node.IsPrivate {
		t.Error("expected private node")
	}

	if !bytes.Equal(node.Version, []byte{0x04, 0x35, 0x83, 0x94}) {
		t.Errorf("unexpected version: %x", node.Version)
	}
}

// Test that covers parseIndex with just a hardened marker and no number
func TestParseIndexJustHardenedMarker(t *testing.T) {
	_, err := ParsePath("m/'")
	if err == nil {
		t.Error("expected error for path with just hardened marker")
	}
}

// Test NewMasterNode with curves that could theoretically error
// (Though in practice, ed25519/curve25519 MasterKey never errors)
func TestNewMasterNodeAllCurves(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	curves := []Curve{
		NewSecp256k1(),
		NewNist256p1(),
		NewEd25519(),
		NewCurve25519(),
	}

	for _, curve := range curves {
		node, err := NewMasterNode(seed, curve)
		if err != nil {
			t.Errorf("NewMasterNode failed for %s: %v", curve.Name(), err)
			continue
		}
		if node == nil {
			t.Errorf("node is nil for %s", curve.Name())
			continue
		}
		if !node.IsPrivate {
			t.Errorf("expected private node for %s", curve.Name())
		}
	}
}

// Test NewMasterNode error path using mock curve (line 66-67)
func TestNewMasterNodeError(t *testing.T) {
	curve := &mockErrorCurve{
		name:         "mock",
		masterKeyErr: errors.New("master key generation failed"),
	}

	_, err := NewMasterNode([]byte("seed"), curve)
	if err == nil {
		t.Error("expected error from NewMasterNode")
	}
	if err.Error() != "master key generation failed" {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test Derive private child error path (line 159-161)
func TestDerivePrivateChildError(t *testing.T) {
	curve := &mockErrorCurve{
		name:          "mock",
		derivePrivErr: errors.New("private derivation failed"),
	}

	node := &Node{
		Curve:     curve,
		IsPrivate: true,
		PrivKey:   make([]byte, 32),
		PubKey:    make([]byte, 33),
		ChainCode: make([]byte, 32),
		Depth:     0,
		ParentFP:  []byte{0, 0, 0, 0},
		Index:     0,
	}

	_, err := node.Derive(0x80000000)
	if err == nil {
		t.Error("expected error from Derive")
	}
	if err.Error() != "private derivation failed" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseIndexEmptyString(t *testing.T) {
	_, err := parseIndex("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestParseKeyDataErrors(t *testing.T) {
	curve := NewSecp256k1()

	// Private key with invalid length
	_, _, err := parseKeyData(make([]byte, 10), true, curve)
	if err == nil {
		t.Error("expected error for invalid private key length")
	}

	// Public key with invalid length
	_, _, err = parseKeyData(make([]byte, 10), false, curve)
	if err == nil {
		t.Error("expected error for invalid public key length")
	}
}

func TestWeierstrassPublicChildHardenedIndexDirect(t *testing.T) {
	pubKey := make([]byte, 33)
	pubKey[0] = 0x02
	chainCode := make([]byte, 32)

	_, _, err := deriveWeierstrassPublicChild(pubKey, chainCode, 0x80000000, secp256k1.S256(), nil)
	if err == nil {
		t.Error("expected error for hardened index")
	}
	if err.Error() != "cannot derive hardened child from public key" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCurveNames(t *testing.T) {
	curves := []struct {
		curve    Curve
		expected string
	}{
		{NewSecp256k1(), "secp256k1"},
		{NewNist256p1(), "nist256p1"},
		{NewEd25519(), "ed25519"},
		{NewCurve25519(), "curve25519"},
	}

	for _, tc := range curves {
		if tc.curve.Name() != tc.expected {
			t.Errorf("expected name %s, got %s", tc.expected, tc.curve.Name())
		}
	}
}

func TestNist256p1PublicDerivation(t *testing.T) {
	curve := NewNist256p1()

	// Generate a master key
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Derive m/0 (private)
	childPriv, _ := master.Derive(0)

	// Create public node for m/0
	pubParent := &Node{
		Curve:     curve,
		IsPrivate: false,
		PubKey:    childPriv.PubKey,
		ChainCode: childPriv.ChainCode,
		Depth:     childPriv.Depth,
		ParentFP:  childPriv.ParentFP,
		Index:     childPriv.Index,
	}

	// Derive m/0/1 (public) from public parent
	childPub, err := pubParent.Derive(1)
	if err != nil {
		t.Fatalf("failed public derivation: %v", err)
	}

	// Verify against private derivation: m/0 -> m/0/1
	childPrivFromPriv, _ := childPriv.Derive(1)

	if hex.EncodeToString(childPub.PubKey) != hex.EncodeToString(childPrivFromPriv.PubKey) {
		t.Errorf("public derivation mismatch:\nGot:  %x\nWant: %x", childPub.PubKey, childPrivFromPriv.PubKey)
	}

	// Test error: Hardened derivation from public parent
	_, err = pubParent.Derive(0x80000000)
	if err == nil {
		t.Error("expected error for hardened derivation from public parent, got nil")
	}
	if err.Error() != "cannot derive hardened child from public parent" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNodeString(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// String() returns safe representation (no private key exposed)
	expected := "Node{curve=secp256k1, depth=0, private=true}"
	if master.String() != expected {
		t.Errorf("expected String() to return %q, got %q", expected, master.String())
	}

	pubNode, _ := NewNodeFromExtendedKey(master.XPub(), curve)
	expectedPub := "Node{curve=secp256k1, depth=0, private=false}"
	if pubNode.String() != expectedPub {
		t.Errorf("expected String() to return %q, got %q", expectedPub, pubNode.String())
	}
}

func TestDerivePathErrors(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	tests := []struct {
		path      string
		errString string
	}{
		{"", ""}, // Empty path returns nil error
		{"m/abc", "invalid path part \"abc\": strconv.ParseUint: parsing \"abc\": invalid syntax"},
		{"m/1/2h/x", "invalid path part \"x\": strconv.ParseUint: parsing \"x\": invalid syntax"},
		{"1/2", "path must start with 'm/'"},
	}

	for _, tc := range tests {
		_, err := master.DerivePath(tc.path)
		if tc.path == "" {
			if err != nil {
				t.Errorf("expected nil error for empty path, got %v", err)
			}
			continue
		}

		if err == nil {
			t.Errorf("expected error for path %s, got nil", tc.path)
		} else if err.Error() != tc.errString {
			t.Errorf("path %s: expected error %q, got %q", tc.path, tc.errString, err.Error())
		}
	}
}

func TestNewNodeFromExtendedKeyErrors(t *testing.T) {
	curve := NewSecp256k1()

	tests := []struct {
		name      string
		key       string
		errString string
	}{
		{
			name:      "Invalid Base58",
			key:       "invalid-base58-chars-0OIl",
			errString: "invalid extended key encoding (neither base58 nor bech32)", // was "invalid base58check length"
		},
		{
			name: "Invalid Length",
			// valid checksum but wrong length
			// base58CheckEncode handles arbitrary length, so we construct a valid check-encoded string of wrong length
			key:       base58.CheckEncode(make([]byte, 10)),
			errString: "invalid extended key length",
		},
	}

	// Add test cases that require manual construction of invalid payloads to pass base58CheckDecode
	// but fail NewNodeFromExtendedKey validation.

	// Helper to create a valid-looking 78-byte payload and modify it
	createPayload := func(mod func([]byte)) string {
		data := make([]byte, 78)
		// Set valid private key version
		copy(data[0:4], []byte{0x04, 0x88, 0xAD, 0xE4})
		// Set valid key data (0x00 + 32 bytes)
		data[45] = 0x00
		for i := 46; i < 78; i++ {
			data[i] = 1
		}

		mod(data)
		return base58.CheckEncode(data)
	}

	tests = append(tests,
		struct{ name, key, errString string }{
			"Invalid Private Key Prefix",
			createPayload(func(d []byte) {
				d[45] = 0x01 // Should be 0x00 for private key
			}),
			"invalid private key prefix",
		},
		struct{ name, key, errString string }{
			"Invalid Public Key Prefix",
			createPayload(func(d []byte) {
				// Set public key version
				copy(d[0:4], []byte{0x04, 0x88, 0xB2, 0x1E})
				d[45] = 0x04 // Should be 0x02 or 0x03
			}),
			"invalid public key prefix",
		},
		struct{ name, key, errString string }{
			"Depth 0 with Non-Zero Index",
			createPayload(func(d []byte) {
				d[4] = 0x00 // Depth 0
				d[9] = 0x01 // Index non-zero (offsets: ver 4, depth 1, parentFP 4, index 4 -> 9)
			}),
			"index must be 0 for depth 0",
		},
		struct{ name, key, errString string }{
			"Depth 0 with Non-Zero Parent Fingerprint",
			createPayload(func(d []byte) {
				d[4] = 0x00 // Depth 0
				d[5] = 0x01 // ParentFP non-zero
			}),
			"parent fingerprint must be 0 for depth 0",
		},
	)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewNodeFromExtendedKey(tc.key, curve)
			if err == nil {
				t.Errorf("expected error, got nil")
			} else if tc.errString != "" && err.Error() != tc.errString {
				t.Errorf("expected error %q, got %q", tc.errString, err.Error())
			}
		})
	}
}

func TestTestnetKeys(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Create a testnet node
	testnetNode := &Node{
		Curve:     curve,
		IsPrivate: true,
		PrivKey:   master.PrivKey,
		PubKey:    master.PubKey,
		ChainCode: master.ChainCode,
		Depth:     master.Depth,
		ParentFP:  master.ParentFP,
		Index:     master.Index,
		Version:   []byte{0x04, 0x35, 0x83, 0x94}, // tprv
	}

	xpub := testnetNode.XPub()
	// tpub prefix in hex is roughly 043587cf
	decoded, _ := base58.CheckDecode(xpub)
	if hex.EncodeToString(decoded[0:4]) != "043587cf" {
		t.Errorf("expected tpub version bytes 043587cf, got %x", decoded[0:4])
	}
}

func TestInvalidPublicKeyDerivation(t *testing.T) {
	curve := NewNist256p1()

	// Create a public node with invalid public key data (not a valid point)
	invalidPubKey := make([]byte, 33)
	for i := range invalidPubKey {
		invalidPubKey[i] = 0xFF
	}

	node := &Node{
		Curve:     curve,
		IsPrivate: false,
		PubKey:    invalidPubKey,
		ChainCode: make([]byte, 32),
	}

	_, err := node.Derive(0)
	if err == nil {
		t.Error("expected error for invalid public key, got nil")
	}
}

func TestNodeWipe(t *testing.T) {
	seed := []byte("seed")
	node, err := NewMasterNode(seed, NewSecp256k1())
	if err != nil {
		t.Fatalf("NewMasterNode failed: %v", err)
	}

	privKeyCopy := make([]byte, len(node.PrivKey))
	copy(privKeyCopy, node.PrivKey)
	chainCodeCopy := make([]byte, len(node.ChainCode))
	copy(chainCodeCopy, node.ChainCode)

	node.Wipe()

	// Check PrivKey is zeroed
	for i, b := range node.PrivKey {
		if b != 0 {
			t.Errorf("PrivKey byte at index %d not zeroed: %d", i, b)
		}
	}
	if bytes.Equal(node.PrivKey, privKeyCopy) {
		t.Error("PrivKey was not modified")
	}

	// Check ChainCode is zeroed
	for i, b := range node.ChainCode {
		if b != 0 {
			t.Errorf("ChainCode byte at index %d not zeroed: %d", i, b)
		}
	}
	if bytes.Equal(node.ChainCode, chainCodeCopy) {
		t.Error("ChainCode was not modified")
	}
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		expected      []uint32
		expectedError bool
	}{
		{
			name:     "Empty path (root)",
			path:     "m",
			expected: nil,
		},
		{
			name:     "Simple path",
			path:     "m/0/1/2",
			expected: []uint32{0, 1, 2},
		},
		{
			name:     "Hardened path",
			path:     "m/0'/1h/2H",
			expected: []uint32{0x80000000, 0x80000001, 0x80000002},
		},
		{
			name:     "Mixed path",
			path:     "m/44'/0/0'",
			expected: []uint32{0x80000000 + 44, 0, 0x80000000},
		},
		{
			name:          "Invalid start",
			path:          "n/0",
			expectedError: true,
		},
		{
			name:          "Invalid number",
			path:          "m/abc",
			expectedError: true,
		},
		{
			name:          "Empty part",
			path:          "m//1",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			indices, err := ParsePath(tc.path)
			if tc.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(indices) != len(tc.expected) {
				t.Errorf("Expected %d indices, got %d", len(tc.expected), len(indices))
				return
			}

			for i, idx := range indices {
				if idx != tc.expected[i] {
					t.Errorf("Start index %d: expected %d, got %d", i, tc.expected[i], idx)
				}
			}
		})
	}
}

package bech32

import (
	"fmt"
	"strings"
)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var generator = []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

// Encode encodes the given data using the Bech32 format with the given hrp.
// The data must be 5-bit integers.
func Encode(hrp string, data []byte) (string, error) {
	// Standard Bech32 has a 90-char limit, but Cardano uses this for large keys.
	// We relax the limit here.
	if len(hrp) < 1 {
		return "", fmt.Errorf("invalid hrp: empty")
	}
	for p, c := range hrp {
		if c < 33 || c > 126 {
			return "", fmt.Errorf("invalid character human-readable part: hrp[%d]=%d", p, c)
		}
	}
	if strings.ToUpper(hrp) != hrp && strings.ToLower(hrp) != hrp {
		return "", fmt.Errorf("mixed case hrp")
	}
	hrp = strings.ToLower(hrp)
	checksum := createChecksum(hrp, data)
	combined := append(data, checksum...)
	var ret strings.Builder
	ret.WriteString(hrp)
	ret.WriteString("1")
	for _, p := range combined {
		if p >= byte(len(charset)) {
			return "", fmt.Errorf("invalid data byte: %d", p)
		}
		ret.WriteByte(charset[p])
	}
	return ret.String(), nil
}

// Decode decodes a Bech32 string.
// Returns the human-readable part and the data part (5-bit integers).
func Decode(bech string) (string, []byte, error) {
	// Standard Bech32 has a 90-char limit, but Cardano uses this for large keys.
	// We relax the limit here.
	if strings.ToLower(bech) != bech && strings.ToUpper(bech) != bech {
		return "", nil, fmt.Errorf("mixed case")
	}
	bech = strings.ToLower(bech)
	pos := strings.LastIndex(bech, "1")
	if pos < 1 || pos+7 > len(bech) {
		return "", nil, fmt.Errorf("separator '1' at invalid position: %d", pos)
	}
	hrp := bech[:pos]
	for p, c := range hrp {
		if c < 33 || c > 126 {
			return "", nil, fmt.Errorf("invalid character human-readable part: hrp[%d]=%d", p, c)
		}
	}
	data := make([]byte, 0, len(bech)-pos-1)
	for p, c := range bech[pos+1:] {
		d := strings.IndexRune(charset, c)
		if d == -1 {
			return "", nil, fmt.Errorf("invalid character data part: bech[%d]=%d", p+pos+1, c)
		}
		data = append(data, byte(d))
	}
	if !verifyChecksum(hrp, data) {
		return "", nil, fmt.Errorf("checksum failed")
	}
	return hrp, data[:len(data)-6], nil
}

func polymod(values []int) int {
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []int {
	ret := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		ret = append(ret, int(c>>5))
	}
	ret = append(ret, 0)
	for _, c := range hrp {
		ret = append(ret, int(c&31))
	}
	return ret
}

func verifyChecksum(hrp string, data []byte) bool {
	integers := make([]int, len(data))
	for i, b := range data {
		integers[i] = int(b)
	}
	concat := append(hrpExpand(hrp), integers...)
	return polymod(concat) == 1
}

func createChecksum(hrp string, data []byte) []byte {
	integers := make([]int, len(data))
	for i, b := range data {
		integers[i] = int(b)
	}
	values := append(hrpExpand(hrp), integers...)
	values = append(values, []int{0, 0, 0, 0, 0, 0}...)
	mod := polymod(values) ^ 1
	ret := make([]byte, 6)
	for p := 0; p < 6; p++ {
		ret[p] = byte((mod >> uint(5*(5-p))) & 31)
	}
	return ret
}

// ConvertBits converts a byte slice from one bit size to another (swapping bit order).
// Typically used to convert 8-bit byte arrays to 5-bit arrays for Bech32 encoding and vice versa.
func ConvertBits(data []byte, frombits, tobits byte, pad bool) ([]byte, error) {
	var ret []byte
	acc := 0
	bits := 0
	maxv := (1 << tobits) - 1
	max_acc := (1 << (frombits + tobits - 1)) - 1
	for _, value := range data {
		if value>>frombits != 0 {
			return nil, fmt.Errorf("invalid value (value %d > %d", value, (1<<frombits)-1)
		}
		acc = ((acc << frombits) | int(value)) & max_acc
		bits += int(frombits)
		for bits >= int(tobits) {
			bits -= int(tobits)
			ret = append(ret, byte((acc>>uint(bits))&maxv))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<uint(int(tobits)-bits))&maxv))
		}
	} else if bits >= int(frombits) || ((acc<<uint(int(tobits)-bits))&maxv) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return ret, nil
}

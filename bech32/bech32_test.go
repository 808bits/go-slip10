package bech32

import (
	"bytes"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	hrp := "hello"
	data := []byte{1, 2, 3, 4, 30}

	encoded, err := Encode(hrp, data)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decodedHrp, decodedData, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decodedHrp != hrp {
		t.Errorf("HRP mismatch: got %s, want %s", decodedHrp, hrp)
	}

	if !bytes.Equal(decodedData, data) {
		t.Errorf("Data mismatch: got %v, want %v", decodedData, data)
	}
}

func TestConvertBits(t *testing.T) {
	// 8 bit to 5 bit
	input := []byte{0xff, 0xff} // 11111111 11111111 -> 11111 11111 11111 1
	// 11111 = 31
	// 11111 = 31
	// 11111 = 31
	// 1     = 10000 (padded) = 16
	expected := []byte{31, 31, 31, 16}

	res, err := ConvertBits(input, 8, 5, true)
	if err != nil {
		t.Fatalf("ConvertBits 8->5 failed: %v", err)
	}
	if !bytes.Equal(res, expected) {
		t.Errorf("ConvertBits 8->5 mismatch: got %v, want %v", res, expected)
	}

	// 5 bit to 8 bit
	back, err := ConvertBits(res, 5, 8, false)
	if err != nil {
		t.Fatalf("ConvertBits 5->8 failed: %v", err)
	}
	if !bytes.Equal(back, input) {
		t.Errorf("ConvertBits 5->8 mismatch: got %v, want %v", back, input)
	}
}

package bech32

import (
	"strings"
	"testing"
)

// TestEncodeErrors tests error paths in Encode function
func TestEncodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		hrp     string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty hrp",
			hrp:     "",
			data:    []byte{0, 1, 2},
			wantErr: "invalid hrp: empty",
		},
		{
			name:    "hrp with control character",
			hrp:     "test\x00hrp",
			data:    []byte{0, 1, 2},
			wantErr: "invalid character human-readable part",
		},
		{
			name:    "hrp with DEL character",
			hrp:     "test\x7fhrp",
			data:    []byte{0, 1, 2},
			wantErr: "invalid character human-readable part",
		},
		{
			name:    "mixed case hrp",
			hrp:     "tEsT",
			data:    []byte{0, 1, 2},
			wantErr: "mixed case hrp",
		},
		{
			name:    "data byte out of range (>= 32)",
			hrp:     "test",
			data:    []byte{0, 1, 32}, // 32 is >= len(charset)
			wantErr: "invalid data byte",
		},
		{
			name:    "data byte way out of range",
			hrp:     "test",
			data:    []byte{255},
			wantErr: "invalid data byte",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Encode(tt.hrp, tt.data)
			if err == nil {
				t.Errorf("Encode() expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Encode() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestDecodeErrors tests error paths in Decode function
func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		bech    string
		wantErr string
	}{
		{
			name:    "mixed case string",
			bech:    "tEsT1qqqq",
			wantErr: "mixed case",
		},
		{
			name:    "no separator",
			bech:    "testnochecksum",
			wantErr: "separator '1' at invalid position",
		},
		{
			name:    "separator at position 0",
			bech:    "1test",
			wantErr: "separator '1' at invalid position",
		},
		{
			name:    "data too short after separator (less than 6 chars for checksum)",
			bech:    "test1abc",
			wantErr: "separator '1' at invalid position",
		},
		{
			name:    "hrp with control character",
			bech:    "te\x01st1qqqqqq",
			wantErr: "invalid character human-readable part",
		},
		{
			name:    "invalid character in data part (letter 'b' is valid, 'o' is not)",
			bech:    "test1qqqoqq",
			wantErr: "invalid character data part",
		},
		{
			name:    "checksum failure",
			bech:    "test1qqqqqq",
			wantErr: "checksum failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Decode(tt.bech)
			if err == nil {
				t.Errorf("Decode() expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Decode() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestConvertBitsErrors tests error paths in ConvertBits function
func TestConvertBitsErrors(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		frombits byte
		tobits   byte
		pad      bool
		wantErr  string
	}{
		{
			name:     "value exceeds frombits",
			data:     []byte{32}, // 32 > (1<<5)-1=31
			frombits: 5,
			tobits:   8,
			pad:      false,
			wantErr:  "invalid value",
		},
		{
			name:     "invalid padding (leftover bits too large)",
			data:     []byte{31, 31, 31, 1}, // results in leftover that indicates extra data
			frombits: 5,
			tobits:   8,
			pad:      false,
			wantErr:  "invalid padding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ConvertBits(tt.data, tt.frombits, tt.tobits, tt.pad)
			if err == nil {
				t.Errorf("ConvertBits() expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ConvertBits() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestEncodeUpperCaseHRP tests that uppercase HRP is valid and gets lowercased
func TestEncodeUpperCaseHRP(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	encodedUpper, err := Encode("TEST", data)
	if err != nil {
		t.Fatalf("Encode with uppercase HRP failed: %v", err)
	}

	encodedLower, err := Encode("test", data)
	if err != nil {
		t.Fatalf("Encode with lowercase HRP failed: %v", err)
	}

	if encodedUpper != encodedLower {
		t.Errorf("Uppercase and lowercase HRP should produce same output, got %s and %s", encodedUpper, encodedLower)
	}

	// Verify it starts with lowercase hrp
	if !strings.HasPrefix(encodedUpper, "test1") {
		t.Errorf("Encoded string should start with 'test1', got %s", encodedUpper)
	}
}

// TestDecodeUpperCase tests decoding uppercase bech32 strings
func TestDecodeUpperCase(t *testing.T) {
	// First encode a valid string
	data := []byte{1, 2, 3, 4, 5}
	encoded, err := Encode("test", data)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Decode the uppercase version
	upperEncoded := strings.ToUpper(encoded)
	hrp, decoded, err := Decode(upperEncoded)
	if err != nil {
		t.Fatalf("Decode uppercase failed: %v", err)
	}

	if hrp != "test" {
		t.Errorf("HRP should be 'test', got %s", hrp)
	}

	for i := range data {
		if decoded[i] != data[i] {
			t.Errorf("Data mismatch at index %d: got %d, want %d", i, decoded[i], data[i])
		}
	}
}

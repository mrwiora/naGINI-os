package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltLength = 16 // 16 bytes for salt
	ivLength   = 12 // 12 bytes for GCM IV
	tagLength  = 16 // 16 bytes GCM auth tag
	keyLength  = 32 // 256 bits for AES-256

	// v2Iterations is the PBKDF2 iteration count of the (only) supported format
	v2Iterations = 600000
)

// v2Header is prepended to v2 payloads and authenticated as AES-GCM additional data
var v2Header = []byte{'N', 'G', 'N', 0x02}

// Decrypt decrypts base64-encoded AES-256-GCM encrypted content using the provided passphrase.
//
// The only accepted format is v2 (there is no legacy or unencrypted fallback):
//
//	["NGN" 0x02][16 bytes: Salt][12 bytes: IV][Encrypted Data + Auth Tag]  (header used as AAD, 600k PBKDF2 iterations)
//
// Any failure (invalid base64, missing header, truncated data, wrong passphrase, tampering) returns an error.
func Decrypt(encryptedBase64, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}

	combined, err := decodeBase64(encryptedBase64)
	if err != nil {
		return nil, err
	}

	if !bytes.HasPrefix(combined, v2Header) {
		return nil, fmt.Errorf("not an encrypted naGINI script (missing \"NGN\" v2 header)")
	}
	combined = combined[len(v2Header):]

	// Verify minimum length (salt + iv + auth tag)
	minLength := saltLength + ivLength + tagLength
	if len(combined) < minLength {
		return nil, fmt.Errorf("encrypted data too short (expected at least %d bytes, got %d)", minLength, len(combined))
	}

	// Extract components
	salt := combined[0:saltLength]
	iv := combined[saltLength : saltLength+ivLength]
	encryptedData := combined[saltLength+ivLength:]

	// Derive key using PBKDF2 with SHA256
	key := pbkdf2.Key([]byte(passphrase), salt, v2Iterations, keyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Decrypt and verify
	decrypted, err := gcm.Open(nil, iv, encryptedData, v2Header)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (invalid passphrase or corrupted data): %v", err)
	}

	return decrypted, nil
}

// decodeBase64 decodes standard base64, ignoring surrounding whitespace
func decodeBase64(s string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding: %v", err)
	}
	return decoded, nil
}

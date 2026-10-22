package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// encryptForTest produces a payload (v2 when header is non-nil, the old headerless format otherwise)
func encryptForTest(t *testing.T, plaintext, passphrase string, header []byte, iterations int) []byte {
	t.Helper()
	salt := make([]byte, saltLength)
	iv := make([]byte, ivLength)
	rand.Read(salt)
	rand.Read(iv)
	key := pbkdf2.Key([]byte(passphrase), salt, iterations, keyLength, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte{}, header...)
	out = append(out, salt...)
	out = append(out, iv...)
	return gcm.Seal(out, iv, []byte(plaintext), header)
}

func TestDecryptV2(t *testing.T) {
	raw := encryptForTest(t, "echo hi\n", "correct horse", v2Header, v2Iterations)
	got, err := Decrypt(base64.StdEncoding.EncodeToString(raw)+"\n", "correct horse")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "echo hi\n" {
		t.Errorf("got %q", got)
	}
}

func TestDecryptRejectsLegacyFormat(t *testing.T) {
	// the old headerless format (100k iterations, no AAD) is no longer accepted
	raw := encryptForTest(t, "echo legacy\n", "correct horse", nil, 100000)
	if _, err := Decrypt(base64.StdEncoding.EncodeToString(raw), "correct horse"); err == nil {
		t.Fatal("expected failure for the legacy format")
	}
}

func TestDecryptV2TamperedHeaderFails(t *testing.T) {
	raw := encryptForTest(t, "echo hi\n", "correct horse", v2Header, v2Iterations)
	raw[3] = 0x03 // version byte is authenticated as AAD
	if _, err := Decrypt(base64.StdEncoding.EncodeToString(raw), "correct horse"); err == nil {
		t.Fatal("expected failure for tampered header")
	}
}

func TestDecryptWrongPassphrase(t *testing.T) {
	raw := encryptForTest(t, "echo hi\n", "correct horse", v2Header, v2Iterations)
	if _, err := Decrypt(base64.StdEncoding.EncodeToString(raw), "wrong horse"); err == nil {
		t.Fatal("expected failure for wrong passphrase")
	}
}

func TestDecryptRejectsPlaintext(t *testing.T) {
	if _, err := Decrypt("#!/bin/bash\nrm -rf /\n", "correct horse"); err == nil {
		t.Fatal("expected failure for plaintext input")
	}
}

// publisherVector was produced by nagini-web2/core/crypto.js encrypt("echo from-nagini-web2\n", "correct horse battery")
const publisherVector = "TkdOAgN1Tl7FMD/p1AA/Aa/4l2COrzinFVvYcwQALFv3gE4FodY3cEqojotBCBXAAoahIX86UEXLO67Eiqed4gXnqI0TLA=="

func TestDecryptPublisherVector(t *testing.T) {
	got, err := Decrypt(publisherVector, "correct horse battery")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "echo from-nagini-web2\n" {
		t.Errorf("got %q", got)
	}
}

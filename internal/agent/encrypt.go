package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

// DeriveKey derives a 32-byte AES key from passphrase and salt using Argon2id.
func DeriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}

// EncryptFile encrypts src file content and writes to dst.
// Format: [12-byte nonce][ciphertext+tag]
func EncryptFile(key []byte, src io.Reader, dst io.Writer) error {
	plaintext, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("read plaintext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	if _, err := dst.Write(nonce); err != nil {
		return fmt.Errorf("write nonce: %w", err)
	}
	if _, err := dst.Write(ciphertext); err != nil {
		return fmt.Errorf("write ciphertext: %w", err)
	}
	return nil
}

// DecryptFile decrypts src and writes plaintext to dst.
func DecryptFile(key []byte, src io.Reader, dst io.Writer) error {
	data, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("read ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("new gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	if _, err := dst.Write(plaintext); err != nil {
		return fmt.Errorf("write plaintext: %w", err)
	}
	return nil
}

// HashFile computes SHA256 hash of a file and returns it as a hex string.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// GenerateSalt returns a new random 32-byte salt as a base64-encoded string.
func GenerateSalt() (string, error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

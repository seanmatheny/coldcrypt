package agent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

// encryptChunkSize is the plaintext size of each encryption chunk (4 MiB).
// Peak memory per file during backup is roughly 2 × encryptChunkSize instead
// of 2 × file_size, preventing OOM on large files.
const encryptChunkSize = 4 * 1024 * 1024

// fileMagic identifies the chunked-encryption format.
// Legacy blobs start with a random 12-byte AES-GCM nonce, so a 4-byte ASCII
// sentinel is safe to use as a format discriminator (collision probability ≈ 1/2^32).
var fileMagic = []byte("CCBK")

// DeriveKey derives a 32-byte AES key from passphrase and salt using Argon2id.
func DeriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}

// EncryptFile encrypts src in fixed-size chunks and writes to dst.
//
// On-disk format (v2 chunked):
//
//	[4-byte magic "CCBK"]
//	[4-byte little-endian plaintext chunk size]
//	For each chunk:
//	  [4-byte little-endian data length = nonceSize + len(ciphertext)]
//	  [12-byte random nonce]
//	  [AES-256-GCM ciphertext + 16-byte authentication tag]
//
// Peak memory per file is ~2 × encryptChunkSize regardless of file size.
func EncryptFile(key []byte, src io.Reader, dst io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("new gcm: %w", err)
	}

	// Write magic and plaintext chunk size.
	if _, err := dst.Write(fileMagic); err != nil {
		return fmt.Errorf("write magic: %w", err)
	}
	var chunkHdr [4]byte
	binary.LittleEndian.PutUint32(chunkHdr[:], uint32(encryptChunkSize))
	if _, err := dst.Write(chunkHdr[:]); err != nil {
		return fmt.Errorf("write chunk size header: %w", err)
	}

	nonceSize := gcm.NonceSize()
	plainBuf := make([]byte, encryptChunkSize)
	// Pre-allocate output buffer with capacity for nonce + max ciphertext;
	// gcm.Seal appends to it without reallocating on subsequent iterations.
	encBuf := make([]byte, nonceSize, nonceSize+encryptChunkSize+gcm.Overhead())

	for {
		n, readErr := io.ReadFull(src, plainBuf)
		if n > 0 {
			// Fill nonce with random bytes.
			encBuf = encBuf[:nonceSize]
			if _, err := io.ReadFull(rand.Reader, encBuf); err != nil {
				return fmt.Errorf("nonce: %w", err)
			}
			// Append ciphertext after the nonce.
			ct := gcm.Seal(encBuf, encBuf[:nonceSize], plainBuf[:n], nil)

			// Write 4-byte chunk data length followed by the chunk itself.
			var lenHdr [4]byte
			binary.LittleEndian.PutUint32(lenHdr[:], uint32(len(ct)))
			if _, err := dst.Write(lenHdr[:]); err != nil {
				return fmt.Errorf("write chunk len: %w", err)
			}
			if _, err := dst.Write(ct); err != nil {
				return fmt.Errorf("write chunk data: %w", err)
			}
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read: %w", readErr)
		}
	}
	return nil
}

// DecryptFile decrypts src and writes plaintext to dst.
// It auto-detects the chunked format (v2, magic "CCBK") and the legacy
// single-blob format (v1) so that blobs created before the chunked format
// was introduced remain restorable.
func DecryptFile(key []byte, src io.Reader, dst io.Writer) error {
	// Peek at the first 4 bytes to detect the format.
	var header [4]byte
	if _, err := io.ReadFull(src, header[:]); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	if bytes.Equal(header[:], fileMagic) {
		return decryptChunked(key, src, dst)
	}
	// Legacy (v1) format: the first 4 bytes are part of the random 12-byte nonce.
	return decryptLegacy(key, header[:], src, dst)
}

// decryptChunked decrypts a v2 chunked blob.  src is positioned just after the
// 4-byte magic.
func decryptChunked(key []byte, src io.Reader, dst io.Writer) error {
	// Read the stored plaintext chunk size for sanity-checking data lengths.
	var chunkSizeHdr [4]byte
	if _, err := io.ReadFull(src, chunkSizeHdr[:]); err != nil {
		return fmt.Errorf("read chunk size header: %w", err)
	}
	storedChunkSize := binary.LittleEndian.Uint32(chunkSizeHdr[:])

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("new gcm: %w", err)
	}

	nonceSize := uint32(gcm.NonceSize())
	// maxDataLen caps the per-chunk allocation to guard against corrupt headers.
	maxDataLen := storedChunkSize + nonceSize + uint32(gcm.Overhead())

	for {
		var lenHdr [4]byte
		_, err := io.ReadFull(src, lenHdr[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read chunk length: %w", err)
		}
		dataLen := binary.LittleEndian.Uint32(lenHdr[:])
		if dataLen > maxDataLen {
			return fmt.Errorf("chunk data length %d exceeds maximum %d", dataLen, maxDataLen)
		}

		chunk := make([]byte, dataLen)
		if _, err := io.ReadFull(src, chunk); err != nil {
			return fmt.Errorf("read chunk data: %w", err)
		}
		if dataLen < nonceSize {
			return fmt.Errorf("chunk too short")
		}

		plaintext, err := gcm.Open(nil, chunk[:nonceSize], chunk[nonceSize:], nil)
		if err != nil {
			return fmt.Errorf("decrypt chunk: %w", err)
		}
		if _, err := dst.Write(plaintext); err != nil {
			return fmt.Errorf("write chunk plaintext: %w", err)
		}
	}
	return nil
}

// decryptLegacy decrypts a v1 (pre-chunked) blob.
// firstBytes contains the 4 bytes already consumed from src.
// NOTE: this loads the entire ciphertext into memory; it exists only for
// backward-compatibility with blobs encrypted before the chunked format.
func decryptLegacy(key []byte, firstBytes []byte, src io.Reader, dst io.Writer) error {
	rest, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("read ciphertext: %w", err)
	}
	data := append(firstBytes, rest...)

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
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
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

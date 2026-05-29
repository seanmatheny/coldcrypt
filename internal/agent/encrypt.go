package agent

import (
	"compress/gzip"
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

// encryptChunkSize is the plaintext size of each encryption chunk (32 MiB).
// Peak memory per file during backup is roughly 2 × encryptChunkSize.
const encryptChunkSize = 32 * 1024 * 1024

// fileMagic is the 4-byte header that identifies the chunked-encryption format
// (uncompressed plaintext).
var fileMagic = []byte("CCBK")

// fileMagicCompressed is the 4-byte header for the compressed+encrypted format.
// Plaintext is gzip-compressed before being fed into the chunked encryption
// layer, allowing transparent decompression on restore.
var fileMagicCompressed = []byte("CCZK")

// DeriveKey derives a 32-byte AES key from passphrase and salt using Argon2id.
func DeriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}

// EncryptFile encrypts src in fixed-size chunks and writes to dst.
//
// On-disk format (v2 chunked, magic "CCBK"):
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
	return encryptFileWithMagic(fileMagic, key, src, dst)
}

// CompressAndEncryptFile gzip-compresses src and then encrypts it using the
// same chunked AES-256-GCM scheme as EncryptFile, writing a "CCZK"-magic blob
// to dst.  DecryptFile detects the magic automatically and decompresses on
// restore, so existing uncompressed ("CCBK") blobs remain fully compatible.
func CompressAndEncryptFile(key []byte, src io.Reader, dst io.Writer) error {
	pr, pw := io.Pipe()
	compErrCh := make(chan error, 1)
	go func() {
		gz := gzip.NewWriter(pw)
		_, err := io.Copy(gz, src)
		if err == nil {
			err = gz.Close()
		}
		pw.CloseWithError(err)
		compErrCh <- err
	}()
	encErr := encryptFileWithMagic(fileMagicCompressed, key, pr, dst)
	compErr := <-compErrCh
	if encErr != nil {
		return encErr
	}
	return compErr
}

// encryptFileWithMagic is the shared implementation used by EncryptFile and
// CompressAndEncryptFile. magic must be exactly 4 bytes.
func encryptFileWithMagic(magic, key []byte, src io.Reader, dst io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("new gcm: %w", err)
	}

	// Write magic and plaintext chunk size.
	if _, err := dst.Write(magic); err != nil {
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

// DecryptFile decrypts a chunked blob written by EncryptFile or
// CompressAndEncryptFile and writes plaintext to dst. The format is detected
// automatically via the 4-byte magic header: "CCBK" blobs are decrypted
// directly; "CCZK" blobs are decrypted and then gzip-decompressed.
func DecryptFile(key []byte, src io.Reader, dst io.Writer) error {
	// Consume and verify the magic header.
	var header [4]byte
	if _, err := io.ReadFull(src, header[:]); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	switch {
	case header == [4]byte(fileMagic):
		return decryptChunked(key, src, dst)
	case header == [4]byte(fileMagicCompressed):
		return decryptChunkedDecompress(key, src, dst)
	default:
		return fmt.Errorf("unrecognised blob format")
	}
}

// decryptChunked decrypts a chunked blob. src is positioned just after the
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

// decryptChunkedDecompress decrypts a "CCZK" blob (src positioned just after
// the 4-byte magic) and gzip-decompresses the resulting plaintext into dst.
func decryptChunkedDecompress(key []byte, src io.Reader, dst io.Writer) error {
	pr, pw := io.Pipe()
	decErrCh := make(chan error, 1)
	go func() {
		err := decryptChunked(key, src, pw)
		pw.CloseWithError(err)
		decErrCh <- err
	}()

	gz, err := gzip.NewReader(pr)
	if err != nil {
		pr.CloseWithError(err)
		<-decErrCh
		return fmt.Errorf("gzip reader: %w", err)
	}
	_, copyErr := io.Copy(dst, gz)
	gz.Close()
	// Drain the pipe so the decryption goroutine can finish.
	pr.CloseWithError(copyErr)
	decErr := <-decErrCh

	if copyErr != nil {
		return fmt.Errorf("decompress: %w", copyErr)
	}
	return decErr
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

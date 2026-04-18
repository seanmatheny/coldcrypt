package dbdump

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	OpenSSLSaltedPrefix = "Salted__"
	opensslSaltBytes    = 8
	pbkdf2Iterations    = 10000
)

// IsOpenSSLSaltedHeader reports whether a file header is OpenSSL "enc" salted format.
func IsOpenSSLSaltedHeader(header []byte) bool {
	return len(header) >= len(OpenSSLSaltedPrefix) && string(header[:len(OpenSSLSaltedPrefix)]) == OpenSSLSaltedPrefix
}

// EncryptOpenSSLAES256CBC encrypts src into OpenSSL-compatible salted output:
// "Salted__" + 8-byte salt + AES-256-CBC ciphertext with PKCS#7 padding.
//
// This can be decrypted with:
//
//	openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -in dump.enc -out dump.db
func EncryptOpenSSLAES256CBC(passphrase string, src io.Reader, dst io.Writer) error {
	salt := make([]byte, opensslSaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	key, iv := deriveKeyIV(passphrase, salt)

	if _, err := dst.Write([]byte(OpenSSLSaltedPrefix)); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := dst.Write(salt); err != nil {
		return fmt.Errorf("write salt: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher init: %w", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	return encryptCBCWithPKCS7(src, dst, mode, aes.BlockSize)
}

// DecryptOpenSSLAES256CBC decrypts OpenSSL-compatible salted AES-256-CBC input.
func DecryptOpenSSLAES256CBC(passphrase string, src io.Reader, dst io.Writer) error {
	header := make([]byte, len(OpenSSLSaltedPrefix)+opensslSaltBytes)
	if _, err := io.ReadFull(src, header); err != nil {
		return fmt.Errorf("read encrypted header: %w", err)
	}
	if !IsOpenSSLSaltedHeader(header) {
		return fmt.Errorf("unsupported encrypted dump format")
	}
	salt := header[len(OpenSSLSaltedPrefix):]
	key, iv := deriveKeyIV(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher init: %w", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	return decryptCBCWithPKCS7(src, dst, mode, aes.BlockSize)
}

func deriveKeyIV(passphrase string, salt []byte) (key []byte, iv []byte) {
	derived := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, 32+16, sha256.New)
	return derived[:32], derived[32:]
}

func encryptCBCWithPKCS7(src io.Reader, dst io.Writer, mode cipher.BlockMode, blockSize int) error {
	buf := make([]byte, 32*1024)
	pending := make([]byte, 0, blockSize)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			data := append(pending, buf[:n]...)
			full := (len(data) / blockSize) * blockSize
			if full > 0 {
				mode.CryptBlocks(data[:full], data[:full])
				if _, werr := dst.Write(data[:full]); werr != nil {
					return fmt.Errorf("write ciphertext: %w", werr)
				}
			}
			pending = append(pending[:0], data[full:]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read plaintext: %w", err)
		}
	}

	padLen := blockSize - (len(pending) % blockSize)
	padded := append(pending, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	mode.CryptBlocks(padded, padded)
	if _, err := dst.Write(padded); err != nil {
		return fmt.Errorf("write final ciphertext: %w", err)
	}
	return nil
}

func decryptCBCWithPKCS7(src io.Reader, dst io.Writer, mode cipher.BlockMode, blockSize int) error {
	buf := make([]byte, 32*1024)
	pending := make([]byte, 0, blockSize)
	var prevPlain []byte

	for {
		n, err := src.Read(buf)
		if n > 0 {
			data := append(pending, buf[:n]...)
			full := (len(data) / blockSize) * blockSize
			if full > 0 {
				blockBuf := make([]byte, full)
				copy(blockBuf, data[:full])
				mode.CryptBlocks(blockBuf, blockBuf)
				for i := 0; i < len(blockBuf); i += blockSize {
					curr := blockBuf[i : i+blockSize]
					if prevPlain != nil {
						if _, werr := dst.Write(prevPlain); werr != nil {
							return fmt.Errorf("write plaintext: %w", werr)
						}
					}
					prevPlain = append(prevPlain[:0], curr...)
				}
			}
			pending = append(pending[:0], data[full:]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read ciphertext: %w", err)
		}
	}

	if len(pending) != 0 {
		return fmt.Errorf("ciphertext is not aligned to block size")
	}
	if len(prevPlain) == 0 {
		return fmt.Errorf("ciphertext is empty")
	}

	padLen := int(prevPlain[len(prevPlain)-1])
	if padLen <= 0 || padLen > blockSize || padLen > len(prevPlain) {
		return fmt.Errorf("invalid padding")
	}
	for i := len(prevPlain) - padLen; i < len(prevPlain); i++ {
		if int(prevPlain[i]) != padLen {
			return fmt.Errorf("invalid padding")
		}
	}
	if _, err := dst.Write(prevPlain[:len(prevPlain)-padLen]); err != nil {
		return fmt.Errorf("write final plaintext: %w", err)
	}
	return nil
}

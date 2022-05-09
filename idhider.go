package idhider

import (
	"encoding/base32"
	"encoding/binary"
	"strings"

	"golang.org/x/crypto/blowfish"
)

// IDHider wraps a Cipher and provides ID (de)obfuscating operations for
// "internal" (not obfuscated and secret) IDs and "public" (obfuscated) IDs.
type IDHider struct {
	cipher *blowfish.Cipher
}

// NewIDHider creates a Cipher with the provided key.
// The underlying Cipher is blowfish.Cipher, so the key must be chosen
// accordingly (from 1 to 56 bytes).
// A 128-bit (16-byte) key should be fine for the purpose of this package.
func NewIDHider(key []byte) (IDHider, error) {
	cipher, err := blowfish.NewCipher(key)
	return IDHider{
		cipher: cipher,
	}, err
}

// PublicID encrypts the internal ID, thus making an obfuscated public ID,
// which is still an integer.
func (idh IDHider) PublicID(id uint64) uint64 {
	encrypted := make([]byte, 8)
	binID := uint64ToBytes(id)
	idh.cipher.Encrypt(encrypted, binID)
	return bytesToUint64(encrypted)
}

// HumanPublicID encrypts the internal ID just like PublicID, but it returns
// a human-readable representation instead of a (probably very large) integer.
// It uses Crockford's Base 32 to provide such representation.
func (idh IDHider) HumanPublicID(id uint64) string {
	encrypted := make([]byte, 8)
	binID := uint64ToBytes(id)
	idh.cipher.Encrypt(encrypted, binID)
	return crockfordBase32Encode(encrypted)
}

// HumanToID decrypts an obfuscated public ID which is in its human-readable
// form and returns the original internal ID.
func (idh IDHider) HumanToID(s string) uint64 {
	buf := crockfordBase32Decode(s)
	clear := make([]byte, 8)
	idh.cipher.Decrypt(clear, buf)
	return bytesToUint64(clear)
}

func uint64ToBytes(x uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, x)
	return buf
}

func bytesToUint64(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}

// Douglas Crockford's Base 32 alphabet (lowercase)
var crockfordEncoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz")

func crockfordBase32Encode(b []byte) string {
	return strings.Trim(crockfordEncoding.EncodeToString(b), "=")
}

func crockfordBase32Decode(s string) []byte {
	encoding := crockfordEncoding.WithPadding(-1)
	buf, _ := encoding.DecodeString(s)
	return buf
}

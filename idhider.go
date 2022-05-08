package idhider

import (
	"encoding/base32"
	"encoding/binary"
	"strings"

	"golang.org/x/crypto/blowfish"
)

type IDHider struct {
	cipher *blowfish.Cipher
}

func NewIDHider(key []byte) (IDHider, error) {
	cipher, err := blowfish.NewCipher(key)
	return IDHider{
		cipher: cipher,
	}, err
}

func (idh IDHider) PublicID(id uint64) uint64 {
	encrypted := make([]byte, 8)
	binID := uint64ToBytes(id)
	idh.cipher.Encrypt(encrypted, binID)
	return bytesToUint64(encrypted)
}

// Douglas Crockford's Base 32 alphabet (lowercase)
var b32Encoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz")

func (idh IDHider) HumanPublicID(id uint64) string {
	encrypted := make([]byte, 8)
	binID := uint64ToBytes(id)
	idh.cipher.Encrypt(encrypted, binID)
	return crockfordBase32Encode(encrypted)
}

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

func crockfordBase32Encode(b []byte) string {
	return strings.Trim(b32Encoding.EncodeToString(b), "=")
}

func crockfordBase32Decode(s string) []byte {
	encoding := b32Encoding.WithPadding(-1)
	buf, _ := encoding.DecodeString(s)
	return buf
}

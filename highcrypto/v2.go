package highcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"math/rand"

	"github.com/lemon-mint/LEA/golea"
)

//v2 Secure Crypto Chain
type v2 struct {
	aes cipher.Block
	lea cipher.Block
}

//Encrypt block
func (c v2) Encrypt(dst, src []byte) {
	clear := make([]byte, 16, 16)
	tmp := make([]byte, 16, 16)
	copy(tmp, src)
	c.lea.Encrypt(dst, tmp)
	copy(tmp, dst)
	c.aes.Encrypt(dst, tmp)
	copy(tmp, dst)
	c.aes.Encrypt(dst, tmp)
	copy(tmp, dst)
	c.aes.Encrypt(dst, tmp)
	copy(tmp, clear)
}

//Decrypt block
func (c v2) Decrypt(dst, src []byte) {
	clear := make([]byte, 16, 16)
	tmp := make([]byte, 16, 16)
	c.aes.Decrypt(dst, src)
	copy(tmp, dst)
	c.aes.Decrypt(dst, tmp)
	copy(tmp, dst)
	c.aes.Decrypt(dst, tmp)
	copy(tmp, dst)
	c.lea.Decrypt(dst, tmp)
	copy(tmp, clear)
}

//BlockSize 16
func (c v2) BlockSize() int { return 16 }

//NewHighCryptoV2 make crypto
func NewHighCryptoV2(key []byte) cipher.Block {
	if (len(key)*8)%16 != 0 {
		log.Fatalln("Key size Error")
	}
	cryptoChain := v2{}

	cryptoChain.aes, _ = aes.NewCipher(key)
	cryptoChain.lea, _ = golea.NewCipher(key)
	return cryptoChain
}

//EncryptCBCArrayV2 Pad and Encrypt len(dst) == (len(src)/16+1)*16
func EncryptCBCArrayV2(src, key, dst []byte) {
	block := NewHighCryptoV2(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	encrypter := cipher.NewCBCEncrypter(block, iv)
	copy(dst[:16], iv)
	padData := ISO10126Pad(src)
	encrypter.CryptBlocks(dst[16:], padData)
}

//DecryptCBCArrayV2 Unpad and Decrypt len(dst) == len(src)-16
func DecryptCBCArrayV2(src, key []byte) []byte {
	block := NewHighCryptoV2(key)
	iv := make([]byte, 16)
	copy(iv, src[:16])
	tmp := make([]byte, len(src)-16)
	encrypter := cipher.NewCBCDecrypter(block, iv)
	encrypter.CryptBlocks(tmp, src[16:])
	dst := ISO10126UnPad(tmp)
	return dst
}

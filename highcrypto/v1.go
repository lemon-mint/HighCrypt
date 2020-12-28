package highcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"math/rand"

	"golang.org/x/crypto/sha3"
)

//v1 Secure Crypto Chain
type v1 struct {
	aes  cipher.Block
	pre1 []byte
}

//Encrypt block
func (c v1) Encrypt(dst, src []byte) {
	clear := make([]byte, 16, 16)
	tmp := make([]byte, 16, 16)
	tmp[0] = c.pre1[0] ^ src[0]
	tmp[1] = c.pre1[1] ^ src[1]
	tmp[2] = c.pre1[2] ^ src[2]
	tmp[3] = c.pre1[3] ^ src[3]
	tmp[4] = c.pre1[4] ^ src[4]
	tmp[5] = c.pre1[5] ^ src[5]
	tmp[6] = c.pre1[6] ^ src[6]
	tmp[7] = c.pre1[7] ^ src[7]
	tmp[8] = c.pre1[8] ^ src[8]
	tmp[9] = c.pre1[9] ^ src[9]
	tmp[10] = c.pre1[10] ^ src[10]
	tmp[11] = c.pre1[11] ^ src[11]
	tmp[12] = c.pre1[12] ^ src[12]
	tmp[13] = c.pre1[13] ^ src[13]
	tmp[14] = c.pre1[14] ^ src[14]
	tmp[15] = c.pre1[15] ^ src[15]
	c.aes.Encrypt(dst, tmp)
	copy(tmp, dst)
	c.aes.Encrypt(dst, tmp)
	copy(tmp, dst)
	c.aes.Encrypt(dst, tmp)
	copy(tmp, clear)
}

//Decrypt block
func (c v1) Decrypt(dst, src []byte) {
	clear := make([]byte, 16, 16)
	tmp := make([]byte, 16, 16)
	c.aes.Decrypt(dst, src)
	copy(tmp, dst)
	c.aes.Decrypt(dst, tmp)
	copy(tmp, dst)
	c.aes.Decrypt(dst, tmp)
	copy(tmp, dst)
	dst[0] = c.pre1[0] ^ tmp[0]
	dst[1] = c.pre1[1] ^ tmp[1]
	dst[2] = c.pre1[2] ^ tmp[2]
	dst[3] = c.pre1[3] ^ tmp[3]
	dst[4] = c.pre1[4] ^ tmp[4]
	dst[5] = c.pre1[5] ^ tmp[5]
	dst[6] = c.pre1[6] ^ tmp[6]
	dst[7] = c.pre1[7] ^ tmp[7]
	dst[8] = c.pre1[8] ^ tmp[8]
	dst[9] = c.pre1[9] ^ tmp[9]
	dst[10] = c.pre1[10] ^ tmp[10]
	dst[11] = c.pre1[11] ^ tmp[11]
	dst[12] = c.pre1[12] ^ tmp[12]
	dst[13] = c.pre1[13] ^ tmp[13]
	dst[14] = c.pre1[14] ^ tmp[14]
	dst[15] = c.pre1[15] ^ tmp[15]
	copy(tmp, clear)
}

//BlockSize 16
func (c v1) BlockSize() int { return 16 }

//NewHighCryptoV1 make crypto
func NewHighCryptoV1(key []byte) cipher.Block {
	if (len(key)*8)%16 != 0 {
		log.Fatalln("Key size Error")
	}
	cryptoChain := v1{}

	Hash3 := sha3.Sum256(key)
	Hash3 = sha3.Sum256(Hash3[:])
	Hash3 = sha3.Sum256(Hash3[:])
	Hash3 = sha3.Sum256(Hash3[:])
	Hash3 = sha3.Sum256(Hash3[:])
	Hash3 = sha3.Sum256(Hash3[:])
	Hash3 = sha3.Sum256(Hash3[:])
	Hash3 = sha3.Sum256(Hash3[:])
	Hash3 = sha3.Sum256(Hash3[:])
	Hash3 = sha3.Sum256(Hash3[:])

	cryptoChain.aes, _ = aes.NewCipher(key)
	cryptoChain.pre1 = Hash3[:]
	return cryptoChain
}

//EncryptCBCArrayV1 Pad and Encrypt len(dst) == (len(src)/16+1)*16
func EncryptCBCArrayV1(src, key, dst []byte) {
	block := NewHighCryptoV1(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	encrypter := cipher.NewCBCEncrypter(block, iv)
	copy(dst[:16], iv)
	padData := ISO10126Pad(src)
	encrypter.CryptBlocks(dst[16:], padData)
}

//DecryptCBCArrayV1 Unpad and Decrypt len(dst) == len(src)-16
func DecryptCBCArrayV1(src, key []byte) []byte {
	block := NewHighCryptoV1(key)
	iv := make([]byte, 16)
	copy(iv, src[:16])
	tmp := make([]byte, len(src)-16)
	encrypter := cipher.NewCBCDecrypter(block, iv)
	encrypter.CryptBlocks(tmp, src[16:])
	dst := ISO10126UnPad(tmp)
	return dst
}

package highcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"

	"golang.org/x/crypto/sha3"
)

//HighCrypto Secure Crypto Chain
type HighCrypto struct {
	aes  cipher.Block
	pre1 []byte
}

//Encrypt block
func (c HighCrypto) Encrypt(dst, src []byte) {
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
func (c HighCrypto) Decrypt(dst, src []byte) {
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
func (c HighCrypto) BlockSize() int { return 16 }

//NewHighCrypto make crypto
func NewHighCrypto(key []byte) cipher.Block {
	if (len(key)*8)%16 != 0 {
		panic("Key size Error")
	}
	cryptoChain := HighCrypto{}

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

//EncryptCBCArray Pad and Encrypt len(dst) == (len(src)/16+1)*16
func EncryptCBCArray(src, key, dst []byte) {
	block := NewHighCrypto(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	encrypter := cipher.NewCBCEncrypter(block, iv)
	copy(dst[:16], iv)
	padData := ISO10126Pad(src)
	encrypter.CryptBlocks(dst[16:], padData)
}

//DecryptCBCArray Unpad and Decrypt len(dst) == len(src)-16
func DecryptCBCArray(src, key, dst []byte) {
	block := NewHighCrypto(key)
	unpadData := ISO10126UnPad(src[16:])
	iv := make([]byte, 16)
	copy(iv, src[:16])
	encrypter := cipher.NewCBCDecrypter(block, iv)
	encrypter.CryptBlocks(dst, unpadData)
}

//ISO10126Pad padding
func ISO10126Pad(src []byte) []byte {
	dst := make([]byte, (len(src)/16+1)*16)
	copy(dst[:len(src)], src)
	padlen := len(dst) - len(src) - 1
	if padlen > 0 {
		padding := make([]byte, padlen)
		rand.Read(padding)
		copy(dst[len(src):len(src)+padlen], padding)
	}
	dst[len(dst)-1] = byte(padlen) + 1
	return dst
}

//ISO10126UnPad un padding
func ISO10126UnPad(src []byte) []byte {
	padlen := src[len(src)-1]
	return src[:len(src)-int(padlen)]
}

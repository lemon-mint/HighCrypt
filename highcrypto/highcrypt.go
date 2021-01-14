package highcrypto

import (
	"errors"
	"math/rand"
)

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

//ISO10126UnPadWithError un padding
func ISO10126UnPadWithError(src []byte) ([]byte, error) {
	padlen := src[len(src)-1]
	if int(padlen) < len(src) {
		if int(padlen) <= 16 {
			return src[:len(src)-int(padlen)], nil
		}
	}
	return nil, errors.New("Wrong padding")
}

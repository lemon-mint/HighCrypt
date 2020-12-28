package highcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"testing"
)

func TestDecryptCBCArrayV1(t *testing.T) {
	data := []byte("Hello, World!")
	key, _ := hex.DecodeString("036d27a1c90ce2a9eef7bc69ea59e510b87858c1b48780d66a74a9ba03856e9a")
	encrypted, _ := hex.DecodeString("52fdfc072182654f163f5f0f9a621d72e896fcff8a1354265df4a21d64d9b154")
	type args struct {
		src []byte
		key []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			"Hello, World! Test",
			args{src: encrypted, key: key},
			data,
		},
	}

	for i := 0; i < 100000; i++ {
		buf := make([]byte, int(mathrand.Float64()*100))
		encryptedBuf := MakeEncryptBuf(buf)
		Newkey := make([]byte, 32)
		rand.Read(buf)
		rand.Read(Newkey)
		EncryptCBCArrayV1(buf, Newkey, encryptedBuf)
		tests = append(
			tests,
			struct {
				name string
				args args
				want []byte
			}{
				fmt.Sprintf("random test #%v", i),
				args{src: encryptedBuf, key: Newkey},
				buf,
			},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecryptCBCArrayV1(tt.args.src, tt.args.key); !bytes.Equal(got, tt.want) {
				t.Errorf("DecryptCBCArrayV1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecryptCBCArrayV2(t *testing.T) {
	type args struct {
		src []byte
		key []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{}

	for i := 0; i < 100000; i++ {
		buf := make([]byte, int(mathrand.Float64()*100))
		encryptedBuf := MakeEncryptBuf(buf)
		Newkey := make([]byte, 32)
		rand.Read(buf)
		rand.Read(Newkey)
		EncryptCBCArrayV2(buf, Newkey, encryptedBuf)
		tests = append(
			tests,
			struct {
				name string
				args args
				want []byte
			}{
				fmt.Sprintf("random test #%v", i),
				args{src: encryptedBuf, key: Newkey},
				buf,
			},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecryptCBCArrayV2(tt.args.src, tt.args.key); !bytes.Equal(got, tt.want) {
				t.Errorf("DecryptCBCArrayV2() = %v, want %v", got, tt.want)
			}
		})
	}
}

package highcrypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDecryptCBCArray(t *testing.T) {
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecryptCBCArrayV1(tt.args.src, tt.args.key); !bytes.Equal(got, tt.want) {
				t.Errorf("DecryptCBCArray() = %v, want %v", got, tt.want)
			}
		})
	}
}

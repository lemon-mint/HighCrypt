package highcrypto

//MakeEncryptBuf make byte buf
func MakeEncryptBuf(src []byte) []byte {
	buf := make([]byte, (len(src)/16+2)*16)
	return buf
}

package aescfbtool

import (
	"fmt"
	"testing"
)

func TestAESCryptoCFB_Encrypto(t *testing.T) {
	aesCryptoCFB := AESCryptoCFB{Crypto: Crypto{
		Secret: []byte("test"),
	}}
	enRes, _ := aesCryptoCFB.Encrypto([]byte("testString"))
	fmt.Println(string(enRes))
	res, _ := aesCryptoCFB.Decrypto(enRes)
	fmt.Println(string(res))
}

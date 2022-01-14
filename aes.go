package aescfbtool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"log"
)

type Crypto struct {
	source    []byte
	secret    []byte
	encrypted []byte
}

type AESCryptoCFB struct {
	Crypto
	k      []byte
	iv     []byte
	offset []byte
}

func (c *AESCryptoCFB) generateKIV() (err error) {
	K := hmac.New(sha256.New, c.secret)
	IV := hmac.New(md5.New, c.secret)
	_, err = K.Write(c.offset)
	if err != nil {
		return
	}
	_, err = IV.Write(c.offset)
	if err != nil {
		log.Println(err.Error())
		return
	}
	c.k = K.Sum(nil)
	c.iv = IV.Sum(nil)
	return
}

func (c *AESCryptoCFB) Encrypto() (err error) {
	err = c.generateKIV()
	if err != nil {
		return
	}
	aesBlockEncryptor, err := aes.NewCipher(c.k)
	if err != nil {
		return
	}
	aesEncryptor := cipher.NewCFBEncrypter(aesBlockEncryptor, c.iv)
	aesEncryptor.XORKeyStream(c.encrypted, c.source)
	return
}

func (c *AESCryptoCFB) Decrypto() (err error) {
	err = c.generateKIV()
	if err != nil {
		return
	}
	aesBlockDecryptor, err := aes.NewCipher(c.k)
	if err != nil {
		return
	}
	aesDecryptor := cipher.NewCFBDecrypter(aesBlockDecryptor, c.iv)
	aesDecryptor.XORKeyStream(c.source, c.encrypted)
	return
}

// func (c *Crypto) getBlockDecryptor() (blockDecryptor cipher.Block, err error) {
// 	aesBlockDecryptor, err := aes.NewCipher(c.k)
// 	if err != nil {
// 		return
// 	}
// 	dest := make([]byte, 0)
// }

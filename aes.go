package aescfbtool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"log"
)

// Crypto 加密通用Context
type Crypto struct {
	source    []byte
	Secret    []byte
	encrypted []byte
}

// AESCryptoCFB AES-CFB-Context
type AESCryptoCFB struct {
	Crypto
	k      []byte
	iv     []byte
	offset []byte
}

func (c *AESCryptoCFB) generateKIV() (err error) {
	K := hmac.New(sha256.New, c.Secret)
	IV := hmac.New(md5.New, c.Secret)
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

// Encrypto 加密函数
//  @receiver c
//  @return err
func (c *AESCryptoCFB) Encrypto(source []byte) (res []byte, err error) {
	c.source = source
	err = c.generateKIV()
	if err != nil {
		return
	}
	aesBlockEncryptor, err := aes.NewCipher(c.k)
	if err != nil {
		return
	}
	c.encrypted = make([]byte, len(c.source))
	aesEncryptor := cipher.NewCFBEncrypter(aesBlockEncryptor, c.iv)
	aesEncryptor.XORKeyStream(c.encrypted, c.source)
	res = c.encrypted
	return
}

// Decrypto 解密函数
//  @receiver c
//  @return err
func (c *AESCryptoCFB) Decrypto(encrypted []byte) (res []byte, err error) {
	c.encrypted = encrypted
	err = c.generateKIV()
	if err != nil {
		return
	}
	aesBlockDecryptor, err := aes.NewCipher(c.k)
	if err != nil {
		return
	}
	c.source = make([]byte, len(c.encrypted))
	aesDecryptor := cipher.NewCFBDecrypter(aesBlockDecryptor, c.iv)
	aesDecryptor.XORKeyStream(c.source, c.encrypted)
	res = c.source
	return
}

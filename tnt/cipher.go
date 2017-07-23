package tnt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"errors"
	"fmt"
	"io"

	"github.com/Yawning/chacha20"
)

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

type cipherInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

var (
	cipherMethod = map[string]*cipherInfo{
		"aes-128-cfb":   {16, 16, newAESCFBStream},
		"aes-192-cfb":   {24, 16, newAESCFBStream},
		"aes-256-cfb":   {32, 16, newAESCFBStream},
		"aes-128-ctr":   {16, 16, newAESCTRStream},
		"aes-192-ctr":   {24, 16, newAESCTRStream},
		"aes-256-ctr":   {32, 16, newAESCTRStream},
		"rc4-md5":       {16, 16, newRC4MD5Stream},
		"chacha20":      {32, 8, newChaCha20Stream},
		"chacha20-ietf": {32, 12, newChaCha20IETFStream},
	}

	errEmpty = errors.New("empty password")
)

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}
func newAESCTRStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}
func newRC4MD5Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4Key := h.Sum(nil)

	return rc4.NewCipher(rc4Key)
}
func newChaCha20Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	return chacha20.NewCipher(key, iv)
}
func newChaCha20IETFStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	return chacha20.NewCipher(key, iv)
}

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func padKey(password string, keyLen int) (key []byte) {
	const md5Len = 16
	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, md5sum([]byte(password)))

	prev := make([]byte, md5Len)
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(prev, m[start-md5Len:start])
		copy(prev[md5Len:], password)
		copy(m[start:], md5sum(prev))
	}
	return m[:keyLen]
}

// NewCipher create new cipher
func NewCipher(method, password string) (*Cipher, error) {
	if password == "" {
		return nil, errEmpty
	}
	mi, ok := cipherMethod[method]
	if !ok {
		return nil, fmt.Errorf("unsupported crypto method: %s", method)
	}
	key := padKey(password, mi.keyLen)
	c := &Cipher{key: key, info: mi}
	return c, nil
}

// Cipher - crypto struct
type Cipher struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	info *cipherInfo
	iv   []byte
}

func (c *Cipher) initEncrpyt() (iv []byte, err error) {
	if c.iv == nil {
		iv = make([]byte, c.info.ivLen)
		if _, err = io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		c.iv = iv
	}
	c.enc, err = c.info.newStream(c.key, iv, Encrypt)
	return
}
func (c *Cipher) initDecrpt(iv []byte) (err error) {
	c.dec, err = c.info.newStream(c.key, iv, Decrypt)
	return
}
func (c *Cipher) encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}
func (c *Cipher) decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

// Copy copy with initial state.
func (c *Cipher) Copy() *Cipher {
	nc := *c
	nc.enc = nil
	nc.dec = nil
	return &nc
}

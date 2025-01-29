package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const cryptPrefix = "CRYPT#"

var (
	password string
	dictKey  string
	encrypt  bool
)

func init() {
	flag.BoolVar(&encrypt, "encrypt", false, "Encrypt values")
	flag.StringVar(&dictKey, "key", "secrets", "The key in YAML for encryption")
	flag.StringVar(&password, "password", "", "Password for encryption. NOT SAFE!\nIt is better to use the environment variable $YAML_PASSWORD")
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Utility to encrypt/decrypt YAML values (decrypt by default).\n\nUsage: yamlcrypt [options] FILE\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if password == "" {
		password = os.Getenv("YAML_PASSWORD")
	}
	if password == "" {
		fmt.Fprintf(os.Stderr, "ERROR: Password not specified!\n")
		os.Exit(1)
	}

	hasher := md5.New()
	hasher.Write([]byte(password))
	key := hasher.Sum(nil)

	filename := os.Args[len(os.Args)-1]
	m := make(map[interface{}]interface{})
	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "File error: %v\n", err)
		os.Exit(2)
	}

	err = yaml.Unmarshal(yamlFile, m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unmarshal %v\n", err)
		os.Exit(3)
	}

	for k, v := range m[dictKey].(map[interface{}]interface{}) {
		value := v.(string)
		if encrypt {
			if !strings.HasPrefix(value, cryptPrefix) {
				m[dictKey].(map[interface{}]interface{})[k] = cryptPrefix + aesCBCEncrypt(value, key)
			}
		} else {
			if strings.HasPrefix(value, cryptPrefix) {
				value = value[len(cryptPrefix):]
			}
			m[dictKey].(map[interface{}]interface{})[k] = aesCBCDecrypt(value, key)

		}
	}

	yml, err := yaml.Marshal(&m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(4)
	}
	fmt.Printf("---\n%s", string(yml))
}

func aesCBCEncrypt(plaintext string, key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key error: %v\n", err)
		os.Exit(5)
	}

	if plaintext == "" {
		fmt.Fprintf(os.Stderr, "plain content empty\n")
		os.Exit(6)
	}

	content := []byte(plaintext)
	content = pkcs5Padding(content, block.BlockSize())

	ciphertext := make([]byte, aes.BlockSize+len(content))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], content)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

func aesCBCDecrypt(crypt64 string, key []byte) string {
	crypt, err := base64.StdEncoding.DecodeString(crypt64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Base64 decode error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Perhaps not encrypted?\n")
		os.Exit(7)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key error: %v\n", err)
		os.Exit(5)
	}

	if len(crypt) == 0 {
		fmt.Fprintf(os.Stderr, "plain content empty\n")
		os.Exit(6)
	}

	iv := crypt[:aes.BlockSize]
	crypt = crypt[aes.BlockSize:]
	decrypted := make([]byte, len(crypt))

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(decrypted, crypt)

	return string(pkcs5Trimming(decrypted))
}

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

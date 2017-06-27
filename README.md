# go-pkcs7

Simple package to pad and unpad data with PKCS7.

## Details

It's common to use PKCS7 to pad and unpad data when using AES encryption. As far as I can tell, though Go has AES-128 encryption in its standard packages, it doesn't offer PKCS7 padding.

This package is designed to use while you're using the standard AES implementation.

## Usage

```go
import (
	"log"
	"github.com/richkzad/go-pkcs7"
)

original := []byte("hello")

var padded []byte
if padded, err := pkcs7.Pad(original, 16); err != nil {
	log.Fatalln(err)
}

var result []byte
if result, err := pkcs7.Unpad(padded, 16); err != nil {
	log.Fatalln(err)
}
```
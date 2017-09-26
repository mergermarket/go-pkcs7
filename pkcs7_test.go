package pkcs7

import (
	"bytes"
	"fmt"
	"testing"
)

const BLOCK_SIZE = 16

func TestPkcs7(t *testing.T) {

	t.Run("Pads", func(t *testing.T) {
		result, _ := Pad([]byte("1234567890"), BLOCK_SIZE)
		expected := []byte("1234567890\x06\x06\x06\x06\x06\x06")
		if bytes.Equal(result, expected) == false {
			panic(fmt.Sprintf(`Failed to pad - expected "%s" but got "%s"`, expected, result))
		}
	})

	t.Run("Unpads", func(t *testing.T) {
		result, _ := Unpad([]byte("1234567890\x06\x06\x06\x06\x06\x06"), BLOCK_SIZE)
		expected := []byte("1234567890")
		if bytes.Equal(result, expected) == false {
			panic(fmt.Sprintf(`Failed to unpad - expected "%s" but got "%s"`, expected, result))
		}
	})

	t.Run("Handles long", func(t *testing.T) {
		longStr := []byte("123456789012345678901234567890123456789012345678901234567890")
		padded, _ := Pad(longStr, BLOCK_SIZE)
		expected := []byte("123456789012345678901234567890123456789012345678901234567890\x04\x04\x04\x04")
		if bytes.Equal(padded, expected) == false {
			panic(fmt.Sprintf(`Padding wrong - expected "%x" but got "%x"`, expected, padded))
		}

		unpadded, _ := Unpad(padded, BLOCK_SIZE)
		if bytes.Equal(unpadded, longStr) == false {
			panic(fmt.Sprintf(`Failed to handle long value - expected "%s" but got "%s"`, longStr, unpadded))
		}
	})

	t.Run("Handles short", func(t *testing.T) {
		shortStr := []byte("1")
		padded, _ := Pad(shortStr, BLOCK_SIZE)
		expected := []byte("1\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f")
		if bytes.Equal(padded, expected) == false {
			panic(fmt.Sprintf(`Padding wrong - expected "%x" but got "%x"`, expected, padded))
		}

		unpadded, _ := Unpad(padded, BLOCK_SIZE)
		if bytes.Equal(unpadded, shortStr) == false {
			panic(fmt.Sprintf(`Failed to handle short value - expected "%s" but got "%s"`, shortStr, unpadded))
		}
	})

	t.Run("Handles empty", func(t *testing.T) {
		emptyStr := []byte("")
		padded, _ := Pad(emptyStr, BLOCK_SIZE)
		expected := []byte("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")
		if bytes.Equal(padded, expected) == false {
			panic(fmt.Sprintf(`Padding wrong - expected "%x" but got "%x"`, expected, padded))
		}

		unpadded, _ := Unpad(padded, BLOCK_SIZE)
		if bytes.Equal(unpadded, emptyStr) == false {
			panic(fmt.Sprintf(`Failed to handle empty value - expected "%s" but got "%s"`, emptyStr, unpadded))
		}
	})

	t.Run("Handles block size", func(t *testing.T) {
		val := []byte("1234567890ABCDEF")
		padded, _ := Pad(val, BLOCK_SIZE)
		expected := []byte("1234567890ABCDEF\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")
		if bytes.Equal(padded, expected) == false {
			panic(fmt.Sprintf(`Padding wrong - expected "%x" but got "%x"`, expected, padded))
		}

		unpadded, _ := Unpad(padded, BLOCK_SIZE)
		if bytes.Equal(unpadded, val) == false {
			panic(fmt.Sprintf(`Failed to handle block size value - expected "%s" but got "%s"`, val, unpadded))
		}
	})
}

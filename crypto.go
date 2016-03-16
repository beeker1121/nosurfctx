package nosurfctx

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

// Encode the given data to base 64 string
func b64encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Decode the given base 64 string to a byte slice
func b64decode(data string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}

	return decoded
}

// Perform a One-Time Pad on data with the given key
func oneTimePad(data, key []byte) {
	n := len(data)
	if n != len(key) {
		panic("Lengths of slices are not equal")
	}

	for i := 0; i < n; i++ {
		data[i] ^= key[i]
	}
}

// Mask the token to make sure it's unique for each
// request, thereby mitigating the BREACH attack.
func maskToken(data []byte) []byte {
	if len(data) != tokenLength {
		return nil
	}

	// tokenLength*2 == len(enckey + token)
	result := make([]byte, tokenLength*2)
	key := result[:tokenLength]
	token := result[tokenLength:]
	copy(token, data)

	// Generate a random key for this token
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	// OTP it
	oneTimePad(token, key)

	return result
}

// Unmask the token
func unmaskToken(data []byte) []byte {
	if len(data) != tokenLength*2 {
		return nil
	}

	key := data[:tokenLength]
	token := data[tokenLength:]
	oneTimePad(token, key)

	return token
}
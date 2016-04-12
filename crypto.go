package nosurfctx

import (
	"fmt"
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
func oneTimePad(data, key []byte) error {
	n := len(data)
	if n != len(key) {
		return fmt.Errorf("Could not OTP due to length mismatch")
	}

	for i := 0; i < n; i++ {
		data[i] ^= key[i]
	}

	return nil
}

// Mask the token to make sure it's unique for each
// request, thereby mitigating the BREACH attack.
func maskToken(data []byte) ([]byte, error) {
	if len(data) != tokenLength {
		return nil, fmt.Errorf("Data length does not match token length")
	}

	// tokenLength*2 == len(enckey + token)
	result := make([]byte, tokenLength*2)
	key := result[:tokenLength]
	token := result[tokenLength:]
	copy(token, data)

	// Generate a random key for this token
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("Could not generate random key for token: %s", err)
	}

	// OTP it
	if err := oneTimePad(token, key); err != nil {
		return nil, fmt.Errorf("Could not OTP token: %s", err)
	}

	return result, nil
}

// Unmask the token
func unmaskToken(data []byte) ([]byte, error) {
	if len(data) != tokenLength*2 {
		return nil, fmt.Errorf("Data does not match the token length * 2")
	}

	key := data[:tokenLength]
	token := data[tokenLength:]

	if err := oneTimePad(token, key); err != nil {
		return nil, fmt.Errorf("Could not OTP token: %s", err)
	}

	return token, nil
}
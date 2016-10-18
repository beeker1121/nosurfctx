// There are two types of tokens.
//
// The unmasked "real" token consists of 32 random bytes.
// It is stored in a cookie (base64 encoded) and it's the
// "reference" value that sent tokens get compared to.
//
// The masked "sent" token consists of 64 bytes:
// 32 byte key used for one-time pad masking.
// 32 byte "real" token masked with said key.
// It is used as the CSRF token value (base64 encoded
// as well) in forms and/or headers.

package nosurfctx

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"golang.org/x/net/context"
	"io"
	"net/http"
)

const (
	// cookieName is the name of the CSRF cookie.
	cookieName = "csrf_token"
	// formFieldName is the name of the form field.
	formFieldName = "csrf_token"
	// headerName is the name of the CSRF header.
	headerName = "X-CSRF-Token"
	// tokenLength is the token length.
	tokenLength = 32
	// maxAge is the max-age in seconds for the CSRF cookie, 365 days.
	maxAge = 365 * 24 * 60 * 60
)

// key is the key type used by this package for context.
type key int

// csrfKey is the key for storing and retrieving the token from context.
var csrfKey key = 1

// Token gets the token from the given context.
func Token(ctx context.Context) string {
	return ctx.Value(csrfKey).(string)
}

// generateToken generates a new token consisting of random bytes.
func generateToken() ([]byte, error) {
	bytes := make([]byte, tokenLength)

	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, fmt.Errorf("Could not generate random bytes for token: %s", err)
	}

	return bytes, nil
}

// getTokenFromCookie gets the token from the CSRF cookie.
func getTokenFromCookie(r *http.Request) []byte {
	var token []byte

	cookie, err := r.Cookie(cookieName)
	if err == nil {
		token = b64decode(cookie.Value)
	}

	return token
}

// getTokenFromRequest gets the token from the request.
func getTokenFromRequest(r *http.Request) []byte {
	var token string

	// Prefer the header over form value.
	token = r.Header.Get(headerName)

	// Then POST values.
	if len(token) == 0 {
		token = r.PostFormValue(formFieldName)
	}

	// If all else fails, try a multipart value.
	// PostFormValue() will have already called ParseMultipartForm()
	if len(token) == 0 && r.MultipartForm != nil {
		vals := r.MultipartForm.Value[formFieldName]
		if len(vals) != 0 {
			token = vals[0]
		}
	}

	return b64decode(token)
}

// setTokenCookie sets the CSRF cookie containing the given token.
func setTokenCookie(w http.ResponseWriter, token []byte) {
	// Create a new http.Cookie with the base64 encoded masked token.
	cookie := http.Cookie{}
	cookie.Name = cookieName
	cookie.Value = b64encode(token)
	cookie.Path = "/"
	cookie.MaxAge = maxAge

	// Set the cookie.
	http.SetCookie(w, &cookie)
}

// setTokenContext sets the given token to the given context.
// The value stored in context will be the masked and base64 encoded
// token for use in forms and ajax.
func setTokenContext(ctx context.Context, token []byte) (context.Context, error) {
	// Mask the token
	maskedToken, err := maskToken(token)
	if err != nil {
		return ctx, err
	}

	return context.WithValue(ctx, csrfKey, b64encode(maskedToken)), nil
}

// verifyToken verifies the sent token matches the real token.
// realToken should be a base64 decoded 32 byte slice.
// sentToken should be a base64 decoded 64 byte slice.
func verifyToken(realToken, sentToken []byte) (bool, error) {
	realN := len(realToken)
	sentN := len(sentToken)

	if realN != tokenLength || sentN != tokenLength*2 {
		return false, fmt.Errorf("Sent token length does not match real token length")
	}

	// Unmask the sent token.
	sentPlain, err := unmaskToken(sentToken)
	if err != nil {
		return false, err
	}

	// Compare the real token to the sent token using a constant
	// time compare function to prevent info from leaking.
	return subtle.ConstantTimeCompare(realToken, sentPlain) == 1, nil
}

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
	"io"
	"net/http"
	"golang.org/x/net/context"
	"crypto/rand"
	"crypto/subtle"
)

const (
	// The name of the CSRF cookie
	cookieName    = "csrf_token"
	// The name of the form field
	formFieldName = "csrf_token"
	// The name of the CSRF header
	headerName    = "X-CSRF-Token"
	// The token length
	tokenLength   = 32
	// Max-age in seconds for the CSRF cookie. 365 days.
	maxAge        = 365 * 24 * 60 * 60
)

// Unexported key type to prevent context collision with other packages.
type key int

// Our unexported key for storing and retrieving the token from context.
var csrfKey key = 1

// Get the token from the given context.
func Token(ctx context.Context) string {
	return ctx.Value(csrfKey).(string)
}

// Generate a new token consisting of random bytes.
func generateToken() []byte {
	bytes := make([]byte, tokenLength)

	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}

	return bytes
}

// Get the token from the CSRF cookie
func getTokenFromCookie(r *http.Request) []byte {
	var token []byte

	cookie, err := r.Cookie(cookieName)
	if err == nil {
		token = b64decode(cookie.Value)
	}

	return token
}

func getTokenFromRequest(r *http.Request) []byte {
	var token string

	// Prefer the header over form value
	token = r.Header.Get(headerName)

	// Then POST values
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

// Set the CSRF cookie containing the given token.
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

// Set the given token to the given context.
// The value stored in context will be the masked and base64 encoded
// token for use in forms and ajax.
func setTokenContext(ctx context.Context, token []byte) context.Context {
	return context.WithValue(ctx, csrfKey, b64encode(maskToken(token)))
}

// Verify the sent token matches the real token.
// realToken should be a base64 decoded 32 byte slice.
// sentToken should be a base64 decoded 64 byte slice.
func verifyToken(realToken, sentToken []byte) bool {
	realN := len(realToken)
	sentN := len(sentToken)

	if realN != tokenLength || sentN != tokenLength*2 {
		return false
	}

	// Unmask the sent token.
	sentPlain := unmaskToken(sentToken)

	// Compare the real token to the sent token using
	// a constant time compare function to prevent
	// info leakage.
	return subtle.ConstantTimeCompare(realToken, sentPlain) == 1
}
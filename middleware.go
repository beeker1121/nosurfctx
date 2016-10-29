package nosurfctx

import (
	"net/http"
	"net/url"
)

// exemptMethods defines HTTP methods for which we only issue the CSRF token
// for, and do not try verifying.
var exemptMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}

// defaultErrorHandler is the default error handler.
func defaultErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Bad Request", http.StatusBadRequest)
}

// Export the public error handler so it can be modified.
var DefaultErrorHandler = defaultErrorHandler

// Protect is the standard middleware used for protecting routes from CSRF
// attacks, taking into account the exempt HTTP methods.
func Protect(h http.HandlerFunc) http.HandlerFunc {
	return protect(h, true)
}

// ForceProtect is middleware used for potecting routes from CSRF attacks,
// disregarding the exempt HTTP methods.
//
// This, for instance, can be used to protect GET requests sent via AJAX.
func ForceProtect(h http.HandlerFunc) http.HandlerFunc {
	return protect(h, false)
}

// protect is the middleware used for protecting routes from CSRF attacks.
func protect(h http.HandlerFunc, checkExempt bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set Vary header to prevent cookie caching in some browsers.
		w.Header().Add("Vary", "Cookie")

		// Try to get the real token from the CSRF cookie.
		realToken := getTokenFromCookie(r)

		// If the length of the real token does not match tokenLength,
		// it has either been tampered with, or we're migrating onto a
		// new algorithm, or it hasn't been set yet.
		// In any case, we should generate a new one and set it to the
		// cookie and context.
		// If the real token already exists in the cookie and matches
		// tokenLength, we can just set it to the context.
		if len(realToken) != tokenLength {
			token, err := generateToken()
			if err != nil {
				DefaultErrorHandler(w, r)
				return
			}

			setTokenCookie(w, token)

			r, err = setTokenContext(r, token)
			if err != nil {
				DefaultErrorHandler(w, r)
				return
			}
		} else {
			// Create err variable to prevent overwrite of r.
			var err error
			r, err = setTokenContext(r, realToken)
			if err != nil {
				DefaultErrorHandler(w, r)
				return
			}
		}

		// Skip to the success handler if the request method is
		// exempt from CSRF verification.
		if checkExempt && stringInSlice(r.Method, exemptMethods) {
			h(w, r)
			return
		}

		// If the request is secure, we enforce origin check
		// for referrer to prevent MITM of http->https requests.
		if r.URL.Scheme == "https" {
			referrer, err := url.Parse(r.Header.Get("Referrer"))

			// If we can't parse the referrer or it's empty,
			// we assume it's not specified.
			if err != nil || referrer.String() == "" {
				DefaultErrorHandler(w, r)
				return
			}

			// If the referrer doesn't share origin with the request.
			// URL, send a Bad Request error.
			if !sameOrigin(referrer, r.URL) {
				DefaultErrorHandler(w, r)
				return
			}
		}

		// Try to get the sent token from the request.
		sentToken := getTokenFromRequest(r)

		// Verify the token.
		tokenOk, err := verifyToken(realToken, sentToken)
		if err != nil {
			DefaultErrorHandler(w, r)
			return
		}

		if !tokenOk {
			DefaultErrorHandler(w, r)
			return
		}

		// Everything passed, call the next handler.
		h(w, r)
	}
}

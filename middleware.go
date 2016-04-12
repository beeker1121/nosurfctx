package nosurfctx

import (
	"net/http"
	"net/url"
	"golang.org/x/net/context"
	"github.com/julienschmidt/httprouter"
)

// Define our Handler type matching httprouter.Handle
// but with a context.Context parameter.
type csrfHandler func(context.Context, http.ResponseWriter, *http.Request, httprouter.Params)

// Methods which we only issue the CSRF token for and do
// not check for verification.
var exemptMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}

// Our default error handler.
func defaultErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Bad Request", http.StatusBadRequest)
}

// Export the public error handler so it can be modified.
var DefaultErrorHandler = defaultErrorHandler

// Begin takes in a csrfHandler function type and returns
// an httprouter.Handle type for use as the first handler
// in the middleware chain.
func Begin(h csrfHandler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		ctx := context.Background()
		h(ctx, w, r, ps)
	}
}

// For routes that handle both GET and POST requests.
func Protect(h csrfHandler) csrfHandler {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

			ctx, err = setTokenContext(ctx, token)
			if err != nil {
				DefaultErrorHandler(w, r)
				return
			}
		} else {
			// Create err variable to prevent overwrite of ctx.
			var err error
			ctx, err = setTokenContext(ctx, realToken)
			if err != nil {
				DefaultErrorHandler(w, r)
				return
			}
		}

		// Skip to the success handler if the request method is
		// exempt from CSRF verification.
		if stringInSlice(r.Method, exemptMethods) {
			h(ctx, w, r, ps)
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

		// Everything passed, call success handler.
		h(ctx, w, r, ps)
	}
}
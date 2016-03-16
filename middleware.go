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
func defaultErrorHandler(w http.ResponseWriter) {
	http.Error(w, "Bad Request", http.StatusBadRequest)
}

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

		// Try to get the real token from the CSRF cookie
		realToken := getTokenFromCookie(r)

		// If the length of the real token does not match tokenLength,
		// it has either been tampered with, or we're migrating onto a
		// new algorithm, or it hasn't been set yet.
		// In any case, we should generate a new one and set it to the
		// cookie and context.
		// If the real token already exists in the cookie and matches
		// tokenLength, we can just set it to the context.
		if len(realToken) != tokenLength {
			token := generateToken()
			setTokenCookie(w, token)
			ctx = setTokenContext(ctx, token)
		} else {
			ctx = setTokenContext(ctx, realToken)
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
				defaultErrorHandler(w)
				return
			}

			// If the referrer doesn't share origin with the request
			// URL, send a Bad Request error.
			if !sameOrigin(referrer, r.URL) {
				defaultErrorHandler(w)
				return
			}
		}

		// Try to get the sent token from the request
		sentToken := getTokenFromRequest(r)

		if !verifyToken(realToken, sentToken) {
			defaultErrorHandler(w)
			return
		}

		// Everything passed, call success handler
		h(ctx, w, r, ps)
	}
}
package nosurfctx

import (
	"net/url"
)

// stringInSlice checks if the given slice contains the given string.
func stringInSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}

	return false
}

// sameOrigin checks if the given URLs share the same origin (that
// is, they share the host, port, and scheme).
func sameOrigin(u1, u2 *url.URL) bool {
	// Host is either host or host:port
	return (u1.Scheme == u2.Scheme && u1.Host == u2.Host)
}

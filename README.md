# nosurfctx

`nosurfctx` is an HTTP package for Go
that helps you prevent Cross-Site Request Forgery attacks when
using the httprouter multiplexer from Julien Schmidt.

Large portions of this code (almost 100%) is from the awesome
`nosurf` package created by Justinas Stankevičius. I would like to
thank both Julien and Justinas for their amazing work, and all
credit is due to them. Links to each project are below:

nosurf: [https://github.com/justinas/nosurf](https://github.com/justinas/nosurf)
httprouter: [https://github.com/julienschmidt/httprouter](https://github.com/julienschmidt/httprouter)

### Why?
Even though CSRF is a prominent vulnerability,
Go's web-related package infrastructure mostly consists of
micro-frameworks that neither do implement CSRF checks,
nor should they.

`nosurfctx` solves this problem by providing `Begin` and `Protect`
middleware that wraps a `httprouter.Handle` and checks for CSRF attacks
on every non-safe (non-GET/HEAD/OPTIONS/TRACE) method.

### Features

* Supports any `httprouter.Handle` with a `context.Context` parameter.
* `context.Context` object used to pass CSRF token between handlers
instead of a global map and mutex lock.
* Uses masked tokens to mitigate the BREACH attack.
* Has no dependencies outside the Go standard library.

### Example
```go
package main

import (
	"fmt"
	"html/template"
	"net/http"
	"golang.org/x/net/context"
	"github.com/julienschmidt/httprouter"
	"github.com/beeker1121/nosurfctx"
)

var templateString string = `
<!doctype html>
<html>
<body>
{{ if .name }}
<p>Your name: {{ .name }}</p>
{{ end }}
<form action="/" method="POST">
<input type="text" name="name">

<!-- Try removing this or changing its value
     and see what happens -->
<input type="hidden" name="csrf_token" value="{{ .token }}">
<input type="submit" value="Send">
</form>
</body>
</html>
`
var templ = template.Must(template.New("t1").Parse(templateString))

func myFunc(ctx context.Context, w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	data := make(map[string]string)
	data["token"] = nosurfctx.Token(ctx)

	if r.Method == "POST" {
		data["name"] = r.FormValue("name")
	}
	
	templ.Execute(w, data)
}

func main() {
	router := httprouter.New()

	router.GET("/", nosurfctx.Begin(nosurfctx.Protect(myFunc)))
	router.POST("/", nosurfctx.Begin(nosurfctx.Protect(myFunc)))

	fmt.Println("Listening on http://127.0.0.1:8000/")
	http.ListenAndServe(":8000", router)
}
```
package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/", firsthandler)
	http.HandleFunc("/submit", bar)
	http.ListenAndServe(":8080", nil)
}
func getCode(msg string) string {
	h := hmac.New(sha512.New, []byte("hello"))
	h.Write([]byte(msg))
	return fmt.Sprintf("%x", h.Sum(nil))
}
func bar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	code := getCode(email)
	c := http.Cookie{Name: "session", Value: code + "|" + email}
	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func firsthandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}
	isEqual := true
	xs := strings.SplitN(c.Value, "|", 2)
	if len(xs) == 2 {
		cCode := xs[0]
		cEmail := xs[1]

		code := getCode(cEmail)
		isEqual = hmac.Equal([]byte(cCode), []byte(code))
	}
	message := "not logged in"
	if isEqual {
		message = "logged in"
	}
	html := `<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<title>hmac example</title>
		</head>
		<body>
		<h1>hello!/<h1>
<p> cookie value: ` + c.Value + ` </p>
<p>` + message + `</p>
		<form action = "/submit" method = "POST">
			<input type="email" name="email"/>
			<input type="submit"/>
		</form>
		
		</body>
		</html>`
	io.WriteString(w, html)
}

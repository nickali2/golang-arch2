package main

import (
	"crypto/hmac"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"io"
	"net/http"
	"strings"
	"time"
)

func main() {
	http.HandleFunc("/", firsthandler)
	http.HandleFunc("/submit", bar)
	http.ListenAndServe(":8080", nil)
}
func getJwt(msg string) (string, error) {
	key := "ILOVEDOGD"
	type myClaims struct {
		jwt.RegisteredClaims
		Email string `json:"email"`
	}
	claims := myClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		Email: msg,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES512, &claims)
	ss, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("couldn't signing jwt key, %w", err)
	}
	return ss, nil
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
	ss, err := getJwt(email)
	if err != nil {
		http.Error(w, "couldn't get jwt", http.StatusInternalServerError)
		return
	}
	c := http.Cookie{Name: "session", Value: ss + "|" + email}
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

		code, err := getJwt(cEmail)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
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

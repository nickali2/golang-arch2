package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/url"
)

func main() {

	http.HandleFunc("/", defaul)
	http.HandleFunc("/register", register)

	http.ListenAndServe("localhost:8080", nil)
}

func defaul(w http.ResponseWriter, r *http.Request) {
	errmsg := r.FormValue("errormsg")
	username := r.FormValue("erruse")
	password := r.FormValue("errorpass")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>hello</title>
</head>
<body>
<p>%s</p>
<p>%s</p>
<p>%s</p>
<form action="/register" method="post">
    <input name="username" type="text" >
    <input name="password" type="password">
    <input name="register" type="submit">
</form>
</body>
</html>`, errmsg, username, password)
	//io.WriteString(w, html)
}

type userdata struct {
	User map[string][]byte `json:"user"`
}

func register(w http.ResponseWriter, r *http.Request) {
	db := userdata{}
	if r.Method != http.MethodPost {
		erruse := url.QueryEscape("methos was not post")
		http.Redirect(w, r, "/?errormsg="+erruse, http.StatusSeeOther)
		return
	}
	username := r.FormValue("username")
	if username == "" {
		errmsg := url.QueryEscape("username cannot be empty!")
		http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		errpass := url.QueryEscape("password cannot be empty!")
		http.Redirect(w, r, "/?errormsg="+errpass, http.StatusSeeOther)
		return
	}

	hashpass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MaxCost)
	if err != nil {
		http.Error(w, "Ooops!, try again!", http.StatusInternalServerError)
		return
	}

	db.User[username] = hashpass

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

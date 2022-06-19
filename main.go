package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/url"
)

var db = map[string][]byte{}

func main() {

	http.HandleFunc("/", defaul)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)

	http.ListenAndServe("localhost:8080", nil)
}

func defaul(w http.ResponseWriter, r *http.Request) {
	errmsg := r.FormValue("errormsg")
	//username := r.FormValue("errormsg")
	//password := r.FormValue("errormsg")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>hello</title>
</head>
<body>
<p>error: %s</p>
<h1 >register</h1>
<form action="/register" method="post">
    <input name="username" type="text" >
    <input name="password" type="password">
    <input name="register" type="submit">
</form>
<h1>login</h1>
<form action="/login" method="get" >
    <input name="username" type="text" >
    <input name="password" type="password">
    <input name="login" type="submit">

</form>
</body>
</html>`, errmsg)
	//io.WriteString(w, html)
}

//type userdata struct {
//	User map[string][]byte `json:"user"`
//}

//var db = userdata{}

func register(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		errmsg := url.QueryEscape("methos was not post")
		http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
		return
	}
	username := r.FormValue("username")
	if username == "" {
		erruse := url.QueryEscape("username cannot be empty!")
		http.Redirect(w, r, "/?errormsg="+erruse, http.StatusSeeOther)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		errpass := url.QueryEscape("password cannot be empty!")
		http.Redirect(w, r, "/?errormsg="+errpass, http.StatusSeeOther)
		return
	}

	hashpass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Ooops!, try again!", http.StatusInternalServerError)
		return
	}

	db[username] = hashpass

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		errmsg := url.QueryEscape("methos was not get")
		http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
		return
	}
	username := r.FormValue("username")
	if username == "" {
		erruse := url.QueryEscape("username cannot be empty!")
		http.Redirect(w, r, "/?errormsg="+erruse, http.StatusSeeOther)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		errpass := url.QueryEscape("password cannot be empty!")
		http.Redirect(w, r, "/?errormsg="+errpass, http.StatusSeeOther)
		return
	}
	if _, ok := db[username]; !ok {
		errmsg := url.QueryEscape("username or password is not correct")
		http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
		return
	}
	err := bcrypt.CompareHashAndPassword(db[username], []byte(password))
	if err != nil {
		errmsg := url.QueryEscape("username or password is not correct")
		http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
		return
	}
	errmsg := url.QueryEscape("Logged IN! " + username)
	http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
}

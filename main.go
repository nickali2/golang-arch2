package main

import (
	"fmt"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/url"
)

//key using for token creation and signing messages
var key = []byte("my love is here and  i will go vacation in the summer")

//user store password in bcrypted hash and first
type user struct {
	Password []byte
	First    string
}

//db srote key:user , password is bcrypt hash
var db = map[string]user{}

//store sID:username (sessionid) in sessions
var sessions = map[string]string{}

func main() {

	http.HandleFunc("/", defaul)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)

	http.ListenAndServe("localhost:8080", nil)
}

func defaul(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("SessionID")
	if err != nil {
		c = &http.Cookie{Name: "SessionID", Value: ""}
	}

	sID, err := parseToken(c.Value)

	if err != nil {
		log.Println("error index", err)
	}
	var uname string
	if sID != "" {
		uname = sessions[sID]
	}
	var f string
	if user, ok := db[uname]; ok {
		f = user.First
	}
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
<p>if there is error: %s</p>
<p>if you have session, here is username: %s</p>
<p>if you have session, here is firstname: %s</p>
<h1 >register</h1>
<form action="/register" method="post">
	<label for="first">First</label>
    <input name="first" type="text" placeholder="First" id="first" >
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
<form action="/logout" method="post">
    <input type="submit" value="logout">
</form>
</body>
</html>`, errmsg, uname, f)
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

	first := r.FormValue("first")
	if first == "" {
		errpass := url.QueryEscape("first name cannot be empty!")
		http.Redirect(w, r, "/?errormsg="+errpass, http.StatusSeeOther)
		return
	}

	hashpass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Ooops!, try again!", http.StatusInternalServerError)
		return
	}

	db[username] = user{
		Password: hashpass,
		First:    first,
	}

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
	//is there s username in database?
	if _, ok := db[username]; !ok {
		errmsg := url.QueryEscape("username or password is not correct")
		http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
		return
	}
	//hash password of a user
	err := bcrypt.CompareHashAndPassword(db[username].Password, []byte(password))
	if err != nil {
		errmsg := url.QueryEscape("username or password is not correct")
		http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
		return
	}

	uuid, _ := uuid.NewV4()
	suuid := uuid.String()
	sessions[suuid] = username
	token, err := createToken(suuid)
	if err != nil {
		log.Println("server cannot create jwt token! check it! maybe!", err)
		errmsg := url.QueryEscape("server didn't  get enough launch right now, and is not ready. try back later!")
		http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
		return

	}
	c := http.Cookie{Name: "SessionID", Value: token}
	http.SetCookie(w, &c)

	errmsg := url.QueryEscape("Logged IN! " + username)
	http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
}

func logout(w http.ResponseWriter, r *http.Request) {
	//never use get for logout, using a get for logout could be a vulnarability.
	//eg. use get in tag of img!
	if r.Method != http.MethodPost {
		errmsg := url.QueryEscape("methos was not post")
		http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
		return
	}
	c, err := r.Cookie("SessionID")
	if err != nil {
		c = &http.Cookie{Name: "SessionID", Value: ""}
	}

	sID, err := parseToken(c.Value)

	if err != nil {
		log.Println("error index", err)
	}
	//delete sid from sessions
	delete(sessions, sID)

	//get rid of cookie
	c.MaxAge = -1

	http.SetCookie(w, c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

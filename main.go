package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

//db srote key:password , password is bcrypt hash
var db = map[string][]byte{}

//store sID:username (sessionid) in sessions
var sessions = map[string]string{}

func main() {

	http.HandleFunc("/", defaul)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)

	http.ListenAndServe("localhost:8080", nil)
}

func defaul(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("SessionID")
	if err != nil {
		c = &http.Cookie{Name: "SessionID", Value: ""}
	}

	s, err := parseToken(c.Value)

	if err != nil {
		log.Println("error index", err)
	}
	var uname string
	if s != "" {
		uname = sessions[s]
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
</html>`, errmsg, uname)
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

	uuid, _ := uuid.NewV4()
	suuid := uuid.String()
	sessions[suuid] = username
	token := createToken(suuid)
	c := http.Cookie{Name: "SessionID", Value: token}
	http.SetCookie(w, &c)

	errmsg := url.QueryEscape("Logged IN! " + username)
	http.Redirect(w, r, "/?errormsg="+errmsg, http.StatusSeeOther)
}
func createToken(sid string) string {
	key := []byte("my love is here and  i will go vacation in the summer")
	mac := hmac.New(sha512.New, key)
	_, er := mac.Write([]byte(sid))
	if er != nil {
		fmt.Errorf("error, %w", er)
	}
	//to hex
	//token := fmt.Sprintf("%x", mac.Sum(nil))

	//to base64
	token := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return token + "|" + sid
}

//return session id
//get token and seprate signature from session id
func parseToken(token string) (string, error) {
	s := strings.SplitN(token, "|", 2)
	//checking to ensure split return 2 parts
	if len(s) != 2 {
		return "", fmt.Errorf("stop hacking me!")
	}
	b64 := s[0]
	xs, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("error in parsetoken while decoding base64 token, %w", err)
	}
	key := []byte("my love is here and  i will go vacation in the summer")
	mac := hmac.New(sha512.New, key)
	_, er := mac.Write([]byte(s[1]))
	if er != nil {
		fmt.Errorf("error, %w", er)
	}

	newtoken := mac.Sum(nil)
	ok := hmac.Equal(xs, newtoken)
	if !ok {
		return "", fmt.Errorf("not equal sid")
	}
	return s[1], nil

}

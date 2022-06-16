package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"time"
)

//var key = []byte("12378956")

type userClaims struct {
	jwt.RegisteredClaims
	SessionID int64
}

func (u *userClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now(), true) {
		return fmt.Errorf("Token has expired")
	}
	if u.SessionID == 0 {
		return fmt.Errorf("invalid session ID")
	}
	return nil
}

//this method creates new token
func createToken(u *userClaims) (string, error) {
	//this is creting token insinde
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, u)

	signedtoken, err := token.SignedString(keys[currentKid].key)
	if err != nil {
		return "", fmt.Errorf("error in create token when signingtoken , %w", err)
	}
	return signedtoken, nil

}
func generatenewkey() error {
	newkey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newkey)
	if err != nil {
		fmt.Errorf("error in generatingnewkey while generate new key random, %w", err)
	}
	uid, err := uuid.NewV4()
	if err != nil {
		fmt.Errorf("error in generatenewkey while generating kid, %w", err)
	}
	keys[uid.String()] = key{
		key:     newkey,
		created: time.Now(),
	}
	currentKid = uid.String()
	return nil
}

type key struct {
	key     []byte
	created time.Time
}

var currentKid = ""
var keys = map[string]key{}

func parseToken(signedtoken string) (*userClaims, error) {

	token, err := jwt.ParseWithClaims(signedtoken, &userClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("invalid signing algorithm")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("key id is invalid")
		}
		//finding kid in database
		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("key id is invalid")
		}
		return k.key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error in parsetoken while parsing token, %w ", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("error in parsetoke, token is not vallid")
	}
	return token.Claims.(*userClaims), nil
}

//var key = []byte{}

func main() {
	//for i := 1; i <= 64; i++ {
	//	key = append(key, byte(i))
	//}
	pass := "123456789"

	hash, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}

	err = comparePasswors(pass, hash)
	if err != nil {
		log.Fatalln("not logged in")
	}
	log.Println("Succesfully logged in")

	//mac := hmac.New(sha512.New, []byte("123456"))
	//mac.Write([]byte("hello"))
	//exmac := mac.Sum(nil)
	//fmt.Println(len(exmac))

}

// create hash string.
// gie s password in string.
// return hashes strin in []byte and possibleerro.
// if there is no error return nil as error.
func hashPassword(password string) ([]byte, error) {

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("there is an error making hash from password: %w", err)

	}

	return hash, nil

}

func comparePasswors(passwors string, hash []byte) error {
	err := bcrypt.CompareHashAndPassword(hash, []byte(passwors))
	if err != nil {
		return fmt.Errorf("invalid passwors: %w", err)
	}
	return nil
}

func getMAC(message string) ([]byte, error) {
	//mykey := key{key: []byte("123456789")}
	mac := hmac.New(sha512.New, keys[currentKid].key)
	_, err := mac.Write([]byte(message))
	if err != nil {
		return nil, fmt.Errorf("error in getMac write message while hashing: %w", err)
	}
	excpectedmac := mac.Sum(nil)
	return excpectedmac, nil

}
func checkMAC(expMAC, msg []byte) (bool, error) {
	newmac, err := getMAC(string(msg))
	if err != nil {
		return false, fmt.Errorf("there is eror in check mac while getting mac of new msg: %w", err)
	}

	b := hmac.Equal(newmac, expMAC)
	return b, nil
}

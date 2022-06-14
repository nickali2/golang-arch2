package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"log"
	"time"
)

var key = "12378956"

type userClaims struct {
	jwt.RegisteredClaims
	SessionID int64
}

func (u *userClaims) valid() error {
	if !u.VerifyExpiresAt(time.Now(), true) {
		return fmt.Errorf("Token has expired")
	}
	if u.SessionID == 0 {
		return fmt.Errorf("invalid session ID")
	}
	return nil
}

func main() {
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
	mac := hmac.New(sha512.New, []byte(key))
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

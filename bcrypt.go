package main

//
//import (
//	"fmt"
//	"golang.org/x/crypto/bcrypt"
//	"log"
//)
//
//func main() {
//	pass := "123456789"
//
//	hash, err := hashPassword(pass)
//	if err != nil {
//		panic(err)
//	}
//
//	err = comparePasswors(pass, hash)
//	if err != nil {
//		log.Fatalln("not logged in")
//	}
//	log.Println("Succesfully logged in")
//}
//
//func hashPassword(password string) ([]byte, error) {
//	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
//	if err != nil {
//		return nil, fmt.Errorf("there is an error making hash from password: %w", err)
//
//	}
//
//	return hash, nil
//
//}
//
//func comparePasswors(passwors string, hash []byte) error {
//	err := bcrypt.CompareHashAndPassword(hash, []byte(passwors))
//	if err != nil {
//		return fmt.Errorf("invalid passwors: %w", err)
//	}
//	return nil
//}

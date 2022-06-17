package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
)

func main() {
	msg := " this is an email from ali to behnaz, thank you toi share me information , and hel me!"
	password := "ilovedogs"
	key, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	rslt, err := enDecode(key[0:16], msg)

	if err != nil {
		log.Fatalln("errros, ", err)
	}
	fmt.Println(string(rslt))

	rslt2, err := enDecode(key[0:16], string(rslt))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(rslt2))
	//encMsg := encodebase64std(msg)
	//fmt.Printf("my msg: %s, this is encoded msg: %s", msg, encMsg)
	//fmt.Printf(" this is encoded url msg: %s", encodebase64url(msg))
	//decoMsg, err := decodebase64std([]byte(encMsg))
	//if err != nil {
	//	fmt.Printf("there was an error decoding MSG!")
	//}
	//fmt.Printf("decoded msg : %s", decoMsg)

}

func enDecode(key []byte, input string) ([]byte, error) {
	b, errr := aes.NewCipher(key)
	if errr != nil {
		return nil, fmt.Errorf("error in newcier, %w", errr)
	}
	//initialig vector
	//iv := []byte(string(aes.BlockSize))

	//initializingvector
	iv := make([]byte, aes.BlockSize)
	//put random numbers in iv
	buff := &bytes.Buffer{}
	s := cipher.NewCTR(b, iv)
	sw := cipher.StreamWriter{
		S:   s,
		W:   buff,
		Err: nil,
	}
	_, err := sw.Write([]byte(input))
	if errr != nil {
		return nil, fmt.Errorf("eror in write cipher , %w", err)
	}

	return buff.Bytes(), nil

}

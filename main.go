package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
)

func main() {
	msg := " this is an email from ali to behnaz, thank you toi share me information , and hel me!"
	password := "ilovedogs"
	key, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	rslt, iv, err := encod(key[0:32], msg)

	if err != nil {
		log.Fatalln("errros, ", err, "iv= ", iv)
	}
	fmt.Println(string(rslt))

	rslt2, err := decod(key[0:32], iv, string(rslt))
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

func encod(key []byte, input string) ([]byte, []byte, error) {
	//b, errr := aes.NewCipher(key)
	//if errr != nil {
	//	return nil, nil, fmt.Errorf("error in newcier, %w", errr)
	//}
	////initialig vector
	////iv := []byte(string(aes.BlockSize))
	//
	////initializingvector
	//iv := make([]byte, aes.BlockSize)
	////put random numbers in iv
	//_, err := io.ReadFull(rand.Reader, iv)
	//if err != nil {
	//	return nil, nil, fmt.Errorf("error in random, %w", err)
	//}
	buff := &bytes.Buffer{}
	//s := cipher.NewCTR(b, iv)
	//sw := cipher.StreamWriter{
	//	S:   s,
	//	W:   buff,
	//	Err: nil,
	//}

	sw, iv, err := encrypWriter(key, buff)
	if err != nil {
		return nil, iv, fmt.Errorf("eror in write cipher , %w", err)
	}
	_, err = sw.Write([]byte(input))
	if err != nil {
		return nil, iv, fmt.Errorf("eror in write cipher , %w", err)
	}

	return buff.Bytes(), iv, nil

}

//get a key and io.writer and create cipher.
//return iowriter, iv, and an error if exists.
//iv used in decrypting
func encrypWriter(key []byte, wtr io.Writer) (io.Writer, []byte, error) {
	b, errr := aes.NewCipher(key)
	if errr != nil {
		return nil, nil, fmt.Errorf("error in newcier, %w", errr)
	}
	//initialig vector
	//iv := []byte(string(aes.BlockSize))

	//initializingvector
	iv := make([]byte, aes.BlockSize)
	//put random numbers in iv
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, nil, fmt.Errorf("error in random, %w", err)
	}
	//buff := &bytes.Buffer{}
	s := cipher.NewCTR(b, iv)
	return cipher.StreamWriter{
		S:   s,
		W:   wtr,
		Err: nil,
	}, iv, nil
}
func decod(key []byte, ivin []byte, input string) ([]byte, error) {
	b, errr := aes.NewCipher(key)
	if errr != nil {
		return nil, fmt.Errorf("error in newcier, %w", errr)
	}
	//initialig vector
	//iv := []byte(string(aes.BlockSize))

	//initializingvector
	iv := ivin
	//put random numbers in iv
	//_, err := io.ReadFull(rand.Reader, iv)
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

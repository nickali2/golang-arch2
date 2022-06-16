package main

import (
	"encoding/base64"
	"fmt"
)

func main() {
	msg := " this is an email from ali to behnaz, thank you toi share me information , and hel me!"
	encMsg := encodebase64std(msg)
	fmt.Printf("my msg: %s, this is encoded msg: %s", msg, encMsg)
	fmt.Printf(" this is encoded url msg: %s", encodebase64url(msg))
	decoMsg, err := decodebase64std([]byte(encMsg))
	if err != nil {
		fmt.Printf("there was an error decoding MSG!")
	}
	fmt.Printf("decoded msg : %s", decoMsg)

}

func encodebase64std(msg string) string {
	return base64.StdEncoding.EncodeToString([]byte(msg))

}
func encodebase64url(msg string) string {
	return base64.URLEncoding.EncodeToString([]byte(msg))
}
func decodebase64std(encMsg []byte) (string, error) {
	dsc := make([]byte, len(encMsg))
	_, err := base64.StdEncoding.Decode(dsc, encMsg)
	if err != nil {
		return "", fmt.Errorf("error in decodebase while decoding, %w", err)
	}
	return string(dsc), nil

}
func decodeurl(enc string) (string, error) {
	b, err := base64.URLEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("error %w", err)
	}
	return string(b), nil

}

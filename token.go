package main

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type customeClaims struct {
	jwt.RegisteredClaims
	SID string
}

func createToken(sid string) (string, error) {

	myClaim := customeClaims{
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute))},
		SID:              sid,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, myClaim)
	str, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("couldn't sign token, %w", err)
	}
	return str, nil

}

//return session id
//get token and seprate signature from session id
func parseToken(signedToken string) (string, error) {
	token, er := jwt.ParseWithClaims(signedToken, &customeClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, errors.New("encryption algorithm is not valid!")
		}
		return key, nil
	})

	//err will check at default index page, so return error and nil string
	if er != nil {
		return "", fmt.Errorf("couldn't parseclaims in parsetoken, %w", er)
	}
	if !token.Valid {
		return "", fmt.Errorf("token not valid in parsetoken")
	}
	return token.Claims.(*customeClaims).SID, nil
}

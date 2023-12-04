package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}

func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("token has expired")
	}

	if u.SessionID == 0 {
		return fmt.Errorf("invalid session id")
	}

	return nil
}

var key = []byte{}

func main() {
	for i := 1; i <= 64; i++ {
		key = append(key, byte(i))
	}

	pass := "123456789"

	hashedPass, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}

	err = comparePassword(pass, hashedPass)
	if err != nil {
		log.Fatal("not logged in")
	}

	log.Println("logged in!")
}

func hashPassword(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error while generating bcrypt hash from password: %s", err)
	}

	return hash, nil
}

func comparePassword(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	if err != nil {
		return fmt.Errorf("invalid password test push: %s", err)
	}
	return nil
}

func signMessage(msg []byte) ([]byte, error) {
	mac := hmac.New(sha512.New, key)
	_, err := mac.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("error occurred during signing: %s", err)
	}

	sign := mac.Sum(nil)
	return sign, nil
}

func checkSign(msg, sign []byte) (bool, error) {
	newSign, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("error occurred during check signing: %s", err)
	}

	same := hmac.Equal(newSign, sign)
	return same, nil
}

func createToken(c *UserClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("error occurred in createToken while signing in: %s", err)
	}

	return signedToken, nil
}

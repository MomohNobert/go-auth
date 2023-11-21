package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

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

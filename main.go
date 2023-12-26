package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
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

func main() {
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
	mac := hmac.New(sha512.New, keys[currentKid].key)
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
	signedToken, err := token.SignedString(keys[currentKid])
	if err != nil {
		return "", fmt.Errorf("error occurred in createToken while signing in: %s", err)
	}

	return signedToken, nil
}

func generateNewKey() error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("error in generateNewKey: %w", err)
	}

	uid, err := uuid.NewV6()
	if err != nil {
		return fmt.Errorf("error in generating uuid: %w", err)
	}

	keys[uid.String()] = keyToken{
		key:     newKey,
		created: time.Now(),
	}

	currentKid = uid.String()
	return nil
}

type keyToken struct {
	key     []byte
	created time.Time
}

var currentKid = ""
var keys = map[string]keyToken{}

func parseToken(signedToken string) (*UserClaims, error) {
	claims := &UserClaims{}
	t, err := jwt.ParseWithClaims(signedToken, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() == jwt.SigningMethodES512.Alg() {
			return nil, fmt.Errorf("invalid signing algorithm")
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid key id")
		}

		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("invalid key id")
		}

		return k, nil
	})

	if err != nil {
		return nil, fmt.Errorf("error in parsing token while verifying")
	}

	if !t.Valid {
		return nil, fmt.Errorf("error in parsing token, token is not valid")
	}

	claims = t.Claims.(*UserClaims)
	return claims, nil
}

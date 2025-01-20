package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

type JWT struct {
	PrivateKey             *rsa.PrivateKey
	PublicKey              *rsa.PublicKey
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
}

type Config struct {
	Key                    string `yaml:"private_key" env-prefix:"PRIVATEKEY" env-default:""`
	AccessTokenExpiration  int    `yaml:"access_token_expiration" env-prefix:"ACCESSTOKENEXPIRATION" env-default:"3600"`
	RefreshTokenExpiration int    `yaml:"refresh_token_expiration" env-prefix:"PRIVATEKEY" env-default:"36000"`
}

const (
	InvalidToken = "invalid token"
	ExpiredToken = "expired token"
)

var (
	needToProvideAuthTokenURLs = []*regexp.Regexp{
		regexp.MustCompile("^/getchat$"),
	}
	needToProvideRefreshTokenURLs = []*regexp.Regexp{
		regexp.MustCompile("^/refresh$"),
	}
)

// Создает jwt объект с ключами и сроком действия токенов
func New(cfg *Config) (JWT, error) {
	jwt := JWT{}
	var err error
	privateKeyString := cfg.Key
	jwt.AccessTokenExpiration = time.Second * time.Duration(cfg.AccessTokenExpiration)
	jwt.RefreshTokenExpiration = time.Second * time.Duration(cfg.RefreshTokenExpiration)
	if privateKeyString == "" {
		jwt.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return JWT{}, err
		}
		jwt.PublicKey = &jwt.PrivateKey.PublicKey
		return jwt, nil
	}
	keyBytes := convertStringToBytesSlice(privateKeyString)
	jwt.PrivateKey, err = x509.ParsePKCS1PrivateKey(keyBytes)
	jwt.PublicKey = &jwt.PrivateKey.PublicKey
	if err != nil {
		return JWT{}, err
	}
	return jwt, nil
}

// Создаёт jwt объект, если ключ уже существует(это нужно, потому что при отсутствии ключа в cfg файле сервисы пытаются создать его сами, и создают разные ключи)
// Это не очень хорошо, так как gateway зависит от authService, и это стоило бы как-то исправить
func NewWithKey(cfg *Config, key *rsa.PrivateKey) (JWT, error) {
	jwt := JWT{PrivateKey: key, PublicKey: &key.PublicKey,
		AccessTokenExpiration: time.Second * time.Duration(cfg.AccessTokenExpiration), RefreshTokenExpiration: time.Second * time.Duration(cfg.RefreshTokenExpiration)}
	return jwt, nil
}

// Создаёт токены для пользователя по его id. В access лежит id, в refresh ничего
func (j *JWT) CreateTokens(user_id int) (string, string, error) {
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.AccessTokenExpiration)),
		Subject:   strconv.Itoa(user_id),
	}).SignedString(j.PrivateKey)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.RefreshTokenExpiration)),
	}).SignedString(j.PrivateKey)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

// Проверяет валидность токенов
func (j *JWT) ValidateToken(c *fiber.Ctx, token string) (bool, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return j.PublicKey, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			log.Println("Should expire at:", time.Unix(0, int64(claims["exp"].(float64))))
			return false, err
		case errors.Is(err, jwt.ErrSignatureInvalid) || errors.Is(err, jwt.ErrTokenUnverifiable):
			return false, err
		default:
			return false, err
		}
	}
	return true, nil
}

// Фильтрует руты, на которых access или refresh токены не понадобятся
func (j *JWT) AuthFilter(c *fiber.Ctx) bool { //TODO: переделать чтобы была одна функция фильтра вместо двух
	originalURL := strings.ToLower(c.OriginalURL())
	for _, pattern := range needToProvideAuthTokenURLs {
		if pattern.MatchString(originalURL) {
			return false
		}
	}
	return true
}

// -||-
func (j *JWT) RefreshFilter(c *fiber.Ctx) bool {
	originalURL := strings.ToLower(c.OriginalURL())
	for _, pattern := range needToProvideRefreshTokenURLs {
		if pattern.MatchString(originalURL) {
			return false
		}
	}
	return true
}

// Получает id пользователя из access токена
func (j *JWT) GetIDFromToken(token string) (int, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return j.PublicKey, nil
	})
	if err != nil {
		return -1, err
	}
	id, err := getIdFromClaims(claims)
	log.Printf("Got id: %v\n", id)
	if err != nil {
		return -1, err
	}
	return id, nil
}

// Получение id из клеймов токена
func getIdFromClaims(claims jwt.MapClaims) (int, error) {
	idString := claims["sub"].(string)
	user_id, err := strconv.Atoi(idString)
	if err != nil {
		log.Println("Cannot atoi Id from claims")
		return -1, err
	}
	return user_id, nil
}

// Перевод застрингованного слайса байтов в слайс байтов "[1 2 3]" -> []byte{1, 2, 3}
func convertStringToBytesSlice(line string) []byte {
	line = strings.Trim(line, "[]")
	parts := strings.Split(line, " ")
	var bytes []byte
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			panic(err)
		}
		bytes = append(bytes, byte(num))
	}
	return bytes
}

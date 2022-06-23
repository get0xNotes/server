package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"database/sql"
	"encoding/ascii85"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/caarlos0/env/v6"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	_ "github.com/lib/pq"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/pbkdf2"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type config struct {
	Port         int    `env:"PORT"          envDefault:"8080"`
	Origins      string `env:"ORIGINS"       envDefault:"http://localhost:3000"`
	ConnStr      string `env:"POSTGRES_URL"  envDefault:"postgres://postgres@localhost:5432/0xnotes-dev?sslmode=disable"`
	ServerSecret string `env:"SERVER_SECRET" envDefault:"encryption_password"`
	ServerSalt   string `env:"SERVER_SALT"   envDefault:"encryption_salt"`
	JWTSecret    string `env:"JWT_SECRET"    envDefault:"secret"`
}

type noteMetadata struct {
	ID         int
	Modified   int64
	Type       string
	Title      string
	TitleNonce string
}

var cfg config
var AESKey []byte

func main() {
	if err := env.Parse(&cfg); err != nil {
		log.Fatal(err)
	}

	AESKey = pbkdf2.Key([]byte(cfg.ServerSecret), []byte(cfg.ServerSalt), 100000, 32, sha512.New)

	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins: strings.Split(cfg.Origins, ","),
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Accept", "Authorization", "Content-Type", "Access-Control-Allow-Origin"},
	}))

	// Root route
	router.GET("/", func(c *gin.Context) {
		c.Header("content-type", "text/html")
		c.String(http.StatusOK, "<h1>0xNotes API Server</h1>")
	})

	// Signup API route
	router.GET("/api/v1/user/signup", func(c *gin.Context) {
		username := c.Query("username")
		auth := c.Query("auth")

		if username == "" || auth == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Username and authorization key are required",
			})
			return
		}

		// Check username availability
		if available, err := isUsernameAvailable(username); err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Internal server error",
			})
			return
		} else if !available {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Username is not available",
			})
			return
		}

		// Check authorization key validity (format must be hex, length must be 256 bits)
		if _, err := strconv.ParseUint(auth, 16, 64); err != nil || len(auth) != 64 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid authorization key",
			})
			return
		}

		if err := createAccount(username, auth); err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Internal server error",
			})
			return
		}

		not_created, err := isUsernameAvailable(username)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Internal server error",
			})
			return
		}
		if not_created {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Internal server error",
			})
			return
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": true,
			})
		}
	})

	// Username availability API route
	router.GET("/api/v1/user/available", func(c *gin.Context) {
		username := c.Query("username")

		if available, err := isUsernameAvailable(username); err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success":   false,
				"available": false,
				"error":     "Internal server error",
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success":   true,
				"available": available,
			})
		}
	})

	// Session request API route
	router.GET("/api/v1/user/session", func(c *gin.Context) {
		username := c.Query("username")
		auth := c.Query("auth")
		twoFA := c.Query("2fa")
		longSession := false

		if c.Query("long_session") == "1" {
			longSession = true
		}

		if username == "" || auth == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"session": false,
				"error":   "Username and authorization key are required",
			})
			return
		}

		// Verify user authentication
		if valid, err := authUser(username, auth, twoFA); err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"session": false,
				"error":   "Internal server error",
			})
			return
		} else if !valid {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"session": false,
				"error":   "Invalid username, authorization key, or 2FA code",
			})
			return
		}

		// Generate session token
		token, err := createSession(username, longSession)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"session": false,
				"error":   "Internal server error",
			})
			return
		}

		// Return session token
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"session": true,
			"jwt":     token,
		})

	})

	// List notes API route
	router.GET("/api/v1/notes/list", func(c *gin.Context) {
		tokenString := strings.Split(c.Request.Header.Get("Authorization"), " ")[1]
		username := c.Query("username")
		if username == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Username is required",
			})
			return
		}
		valid, err := sessionValid(tokenString, username)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Internal server error",
			})
			return
		}

		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Invalid session",
			})
			return
		} else {
			// Session is valid
			notes, err := listNotes(username)
			if err != nil {
				log.Panic(err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"error":   "Internal server error",
				})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"notes":   notes,
			})
		}
	})

	// TOTP information API route
	router.GET("/api/v1/user/totp", func(c *gin.Context) {
		tokenString := strings.Split(c.Request.Header.Get("Authorization"), " ")[1]
		username := c.Query("username")

		if username == "" || tokenString == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Username and authorization key are required",
			})
			return
		}

		valid, err := sessionValid(tokenString, username)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Internal server error",
			})
			return
		}

		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Invalid session",
			})
			return
		}

		totp, err := getTOTPSecret(username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Internal server error",
			})
			return
		}

		if totp != "" {
			c.JSON(http.StatusOK, gin.H{
				"success":  true,
				"enabled":  true,
				"totp":     totp,
				"totp_uri": provisionTOTPURI(username, totp, "0xNotes"),
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"enabled": false,
			})
		}

	})

	// Enable TOTP API route
	router.GET("/api/v1/user/totp/enable", func(c *gin.Context) {
		tokenString := strings.Split(c.Request.Header.Get("Authorization"), " ")[1]
		username := c.Query("username")

		if username == "" || tokenString == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Username and authorization key are required",
			})
			return
		}

		valid, err := sessionValid(tokenString, username)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Internal server error",
			})
			return
		}

		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Invalid session",
			})
		} else {
			// Session is valid
			totp, err := enableTOTP(username)
			if err != nil || totp == "" {
				log.Panic(err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"error":   "Internal server error",
				})
				return
			}
			if totp != "" {
				c.JSON(http.StatusOK, gin.H{
					"success":  true,
					"totp":     totp,
					"totp_uri": provisionTOTPURI(username, totp, "0xNotes"),
				})
			}
		}
	})

	// Start server
	router.Run(fmt.Sprintf(":%d", cfg.Port))
}

func enableTOTP(username string) (string, error) {
	opts := totp.GenerateOpts{
		Issuer:      "0xNotes",
		AccountName: username,
	}
	key, err := totp.Generate(opts)
	if err != nil {
		return "", err
	}

	db, err := sql.Open("postgres", cfg.ConnStr)
	if err != nil {
		return "", err
	}
	defer db.Close()

	_, err = db.Exec("UPDATE users SET totp = $1 WHERE username = $2", key.Secret(), username)
	if err != nil {
		return "", err
	}

	return key.Secret(), nil
}

func provisionTOTPURI(username string, secret string, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s", username, secret, issuer)
}

func getTOTPSecret(username string) (string, error) {
	db, err := sql.Open("postgres", cfg.ConnStr)
	if err != nil {
		return "", err
	}
	defer db.Close()

	rows, err := db.Query("SELECT totp FROM users WHERE username = $1", username)
	if err != nil {
		return "", err
	}

	// User does not exist
	if !rows.Next() {
		return "", nil
	}

	// Get TOTP key from db
	// TODO: sql: Scan error on column index 0, name "totp": converting NULL to string is unsupported
	var totpKey string
	err = rows.Scan(&totpKey)
	if err != nil {
		return "", err
	}

	return totpKey, nil

}

func listNotes(username string) ([]noteMetadata, error) {
	db, err := sql.Open("postgres", cfg.ConnStr)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, type, server_nonce, title_nonce, title, modified FROM notes WHERE author=$1", username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	notesMetadata := []noteMetadata{}
	for rows.Next() {
		var id int
		var type_ string
		var serverNonce string
		var titleNonce string
		var title string
		var modified time.Time
		if err := rows.Scan(&id, &type_, &serverNonce, &titleNonce, &title, &modified); err != nil {
			return nil, err
		}

		// Note: title is still encrypted by client
		titleDecrypted, err := decryptAESCTR256(title, serverNonce)
		if err != nil {
			return nil, err
		}
		notesMetadata = append(notesMetadata, noteMetadata{ID: id, Modified: modified.Unix(), Type: type_, Title: base64.StdEncoding.EncodeToString(titleDecrypted), TitleNonce: titleNonce})
	}
	return notesMetadata, nil
}

func decryptAESCTR256(ciphertext string, nonce string) ([]byte, error) {
	block, err := aes.NewCipher(AESKey)
	if err != nil {
		return nil, err
	}
	// Nonce is in hex string, convert to []byte
	nonceBytes, err := hex.DecodeString(nonce + "0000000000000000")
	if err != nil {
		return nil, err
	}
	ctr := cipher.NewCTR(block, nonceBytes)

	// Ciphertext is in Ascii85 string, convert to []byte
	ciphertextBytes := make([]byte, ascii85.MaxEncodedLen(len(ciphertext)))
	ndst, _, err := ascii85.Decode(ciphertextBytes, []byte(ciphertext), true)
	ciphertextBytes = ciphertextBytes[:ndst]

	if err != nil {
		return nil, err
	}

	// Decrypt ciphertext
	// Note: plaintext is still encrypted by client, so it's not really a plaintext
	plaintext := make([]byte, len(ciphertextBytes))
	ctr.XORKeyStream(plaintext, ciphertextBytes)

	return plaintext, nil
}

func sessionValid(tokenString string, username string) (bool, error) {
	// Parse tokenString
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})
	if err != nil {
		return false, err
	}

	// Check whether token is valid
	if !token.Valid || username != token.Claims.(jwt.MapClaims)["aud"].(string) {
		return false, nil
	} else {
		return true, nil
	}
}

func createSession(username string, longSession bool) (string, error) {
	expiresIn := 86400 // 24 hours
	if longSession {
		expiresIn = 604800 // 7 days
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"aud": username,
		"exp": time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		"iss": "0xNotes",
	}).SignedString([]byte(cfg.JWTSecret))
}

func authUser(username string, auth string, twoFA string) (bool, error) {
	db, err := sql.Open("postgres", cfg.ConnStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT totp FROM users WHERE username = $1 AND auth = $2", username, auth)
	if err != nil {
		return false, err
	}

	// If rows exist, username and auth key is correct
	if !rows.Next() {
		return false, nil
	}

	// Get TOTP key from db
	// TODO: sql: Scan error on column index 0, name "totp": converting NULL to string is unsupported
	var totpKey string
	err = rows.Scan(&totpKey)
	if err != nil {
		return false, err
	}

	// If totp is empty, 2FA is disabled and user is directly authenticated
	if totpKey == "" {
		return true, nil
	}

	// If 2FA is enabled, check if user has provided a valid 2FA key
	return totp.Validate(twoFA, totpKey), nil

}

func createAccount(username string, auth string) error {
	db, err := sql.Open("postgres", cfg.ConnStr)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO users (username, auth) VALUES ($1, $2)", username, auth)
	if err != nil {
		return err
	}

	return nil
}

func isUsernameAvailable(username string) (bool, error) {
	// Username only contains alphanumeric, dash, underscore, and period
	for _, r := range username {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false, nil
		}
	}

	// Username must be at least 5 characters long
	if len(username) < 5 {
		return false, nil
	}

	db, err := sql.Open("postgres", cfg.ConnStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	// Return false if username is already in database
	rows, err := db.Query("SELECT * FROM users WHERE username = $1", username)
	if err != nil {
		return false, err
	} else {
		if rows.Next() {
			return false, nil
		} else {
			return true, nil
		}
	}
}

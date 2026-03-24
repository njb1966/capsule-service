package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

	reservedUsernames = map[string]bool{
		"www": true, "mail": true, "ftp": true, "smtp": true, "pop": true,
		"imap": true, "api": true, "admin": true, "administrator": true,
		"root": true, "postmaster": true, "hostmaster": true, "webmaster": true,
		"support": true, "help": true, "info": true, "contact": true,
		"abuse": true, "noreply": true, "no-reply": true, "gemcities": true,
		"gemini": true, "capsule": true, "static": true, "assets": true,
		"status": true, "blog": true, "news": true, "about": true,
	}
)

func ValidateUsername(username string) error {
	if len(username) < 3 || len(username) > 32 {
		return fmt.Errorf("username must be 3–32 characters")
	}
	if !usernameRe.MatchString(username) {
		return fmt.Errorf("username may only contain lowercase letters, digits, and hyphens, and may not start or end with a hyphen")
	}
	if reservedUsernames[strings.ToLower(username)] {
		return fmt.Errorf("username is reserved")
	}
	return nil
}

func HashPassword(password string, cost int) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(b), err
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func GenerateToken() (plain, hashed string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	plain = hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(plain))
	hashed = hex.EncodeToString(sum[:])
	return
}

func HashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// StoreVerificationToken stores a new email verification token, invalidating any prior ones.
func StoreVerificationToken(db *sql.DB, userID int64, tokenHash string, expiry time.Time) error {
	_, err := db.Exec(
		`UPDATE email_verifications SET used=1 WHERE user_id=? AND used=0`, userID)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES (?,?,?)`,
		userID, tokenHash, expiry.Unix())
	return err
}

// StoreResetToken stores a new password reset token, invalidating any prior ones.
func StoreResetToken(db *sql.DB, userID int64, tokenHash string, expiry time.Time) error {
	_, err := db.Exec(
		`UPDATE password_reset_tokens SET used=1 WHERE user_id=? AND used=0`, userID)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?,?,?)`,
		userID, tokenHash, expiry.Unix())
	return err
}

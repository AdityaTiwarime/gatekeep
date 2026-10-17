package idp

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"
)

const (
	pbkdfIter    = 210_000 // OWASP 2023 guidance for PBKDF2-HMAC-SHA256
	maxFailures  = 5
	lockDuration = 5 * time.Minute
)

type User struct {
	Username string
	Name     string
	Email    string
	Roles    []string
	salt     []byte
	hash     []byte
}

func NewUser(username, password, name, email string, roles ...string) (*User, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	h, err := pbkdf2.Key(sha256.New, password, salt, pbkdfIter, 32)
	if err != nil {
		return nil, err
	}
	return &User{Username: username, Name: name, Email: email, Roles: roles, salt: salt, hash: h}, nil
}

func (u *User) check(password string) bool {
	h, err := pbkdf2.Key(sha256.New, password, u.salt, pbkdfIter, 32)
	return err == nil && subtle.ConstantTimeCompare(h, u.hash) == 1
}

// dummy is checked against when the username doesn't exist, so a wrong
// username and a wrong password take the same time (no user enumeration).
var dummy, _ = NewUser("", "not-a-real-password", "", "")

// lockout counts recent failed logins per username.
type lockout struct {
	mu   sync.Mutex
	fail map[string][]time.Time
}

func (l *lockout) locked(user string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.fail[user][:0]
	for _, t := range l.fail[user] {
		if now.Sub(t) < lockDuration {
			recent = append(recent, t)
		}
	}
	l.fail[user] = recent
	return len(recent) >= maxFailures
}

func (l *lockout) failed(user string, now time.Time) {
	l.mu.Lock()
	l.fail[user] = append(l.fail[user], now)
	l.mu.Unlock()
}

func (l *lockout) reset(user string) {
	l.mu.Lock()
	delete(l.fail, user)
	l.mu.Unlock()
}

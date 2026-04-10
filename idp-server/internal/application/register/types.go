package register

import (
	"errors"
	"time"
)

var (
	ErrInvalidUsername      = errors.New("invalid username")
	ErrInvalidEmail         = errors.New("invalid email")
	ErrInvalidDisplayName   = errors.New("invalid display name")
	ErrWeakPassword         = errors.New("password does not meet policy")
	ErrUsernameAlreadyUsed  = errors.New("username already exists")
	ErrEmailAlreadyUsed     = errors.New("email already exists")
	ErrUserNotFound         = errors.New("user not found")
	ErrPasswordUpdateFailed = errors.New("password update is not supported by repository")
	ErrUserUnlockFailed     = errors.New("user unlock is not supported by repository")
)

type RegisterInput struct {
	Username      string
	Email         string
	DisplayName   string
	Password      string
	EmailVerified bool
	AutoActivate  bool
}

type RegisterResult struct {
	UserID        int64
	UserUUID      string
	Username      string
	Email         string
	EmailVerified bool
	DisplayName   string
	Status        string
	CreatedAt     time.Time
}

type AdminResetPasswordInput struct {
	UserID      int64
	NewPassword string
}

type AdminResetPasswordResult struct {
	UserID        int64
	Username      string
	PasswordSetAt time.Time
}

type AdminUnlockUserInput struct {
	UserID int64
}

type AdminUnlockUserResult struct {
	UserID     int64
	Username   string
	UnlockedAt time.Time
}

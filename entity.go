package goauth

import "time"

type AuthParams struct {
	UsernameOrEmail string
	Password        string
	Token           string
}

type AuthResult struct {
	Authenticatable Authenticatable
	Strategy        string
}

type Token struct {
	Value     string
	ExpiresIn time.Duration
}

type User struct {
	ID        string
	Username  string
	Email     string
	ExtraData map[string]any
}

func (u *User) GetID() string {
	return u.ID
}

func (u *User) GetUsername() string {
	return u.Username
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetExtraData() map[string]any {
	return u.ExtraData
}

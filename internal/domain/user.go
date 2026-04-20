package domain

import "time"

type User struct {
	ID        int64     `json:"id"`
	Nickname  string    `json:"nickname"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
}

// ContactType определяет способ входа.
type ContactType string

const (
	ContactEmail ContactType = "email"
	ContactPhone ContactType = "phone"
)

// SendCodeRequest — передаём email ИЛИ phone (одно из двух).
type SendCodeRequest struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

// ContactValue возвращает заполненный контакт и его тип.
func (r SendCodeRequest) ContactValue() (string, ContactType, bool) {
	if r.Email != "" {
		return r.Email, ContactEmail, true
	}
	if r.Phone != "" {
		return r.Phone, ContactPhone, true
	}
	return "", "", false
}

// VerifyCodeRequest используется и для входа, и для регистрации.
// Если пользователь новый — поле Nickname обязательно.
type VerifyCodeRequest struct {
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Code     string `json:"code"`
	Nickname string `json:"nickname,omitempty"` // только для новых пользователей
}

func (r VerifyCodeRequest) ContactValue() (string, ContactType, bool) {
	if r.Email != "" {
		return r.Email, ContactEmail, true
	}
	if r.Phone != "" {
		return r.Phone, ContactPhone, true
	}
	return "", "", false
}

type AuthResponse struct {
	AccessToken string `json:"access_token"`
	User        User   `json:"user"`
}

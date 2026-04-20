package validator

import (
	"auth-service/internal/domain"
	"errors"
	"regexp"
	"strings"
)

func ValidateAndNormalize(contact string, ctype domain.ContactType) (string, error) {
	switch ctype {
	case domain.ContactEmail:
		email := strings.ToLower(strings.TrimSpace(contact))
		if !validateEmail(email) {
			return "", errors.New("invalid email")
		}
		return email, nil

	case domain.ContactPhone:
		digits := reNonDigits.ReplaceAllString(contact, "")
		phone := "+" + digits

		if !validatePhone(phone) {
			return "", errors.New("invalid phone")
		}
		return phone, nil
	}

	return "", errors.New("unknown contact type")
}

var reNonDigits = regexp.MustCompile(`\D`)

func validateEmail(email string) bool {
	return len(email) <= 254 &&
		regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`).MatchString(email)
}

func validatePhone(phone string) bool {
	return regexp.MustCompile(`^\+[1-9]\d{7,14}$`).MatchString(phone)
}

// internal/domain/auth/validator.go
package auth

import "github.com/go-playground/validator/v10"

type ValidatorWrapper struct {
	validate *validator.Validate
}

func NewValidator(v *validator.Validate) Validator {
	return &ValidatorWrapper{
		validate: v,
	}
}

func (v *ValidatorWrapper) Validate(i interface{}) error {
	return v.validate.Struct(i)
}

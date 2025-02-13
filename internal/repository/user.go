// internal/repository/user.go
package repository

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"ping-websocket-server/internal/domain/auth"
)

// Define errors at package level
var (
	ErrUserExists      = fmt.Errorf("user already exists")
	ErrUserNotFound    = fmt.Errorf("user not found")
	ErrDatabaseError   = fmt.Errorf("database error")
	ErrInvalidPassword = fmt.Errorf("invalid password")
	ErrInvalidUsername = fmt.Errorf("invalid username")
)

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(ctx context.Context, user *auth.SignupRequest) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Check if user exists
	var existingUsername string
	err = tx.QueryRow(ctx, "SELECT username FROM users WHERE username = $1", user.Username).
		Scan(&existingUsername)
	if err == nil {
		return ErrUserExists // This should now be accessible
	}

	// Insert user
	_, err = tx.Exec(ctx,
		"INSERT INTO users (username, password_hash, email, first_name, last_name) VALUES ($1, $2, $3, $4, $5)",
		user.Username, user.Password, user.Email, user.FirstName, user.LastName)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}

	return tx.Commit(ctx)
}

func (r *UserRepository) GetUserByUsername(ctx context.Context, username string) (*auth.User, error) {
	var user auth.User
	err := r.db.QueryRow(ctx,
		"SELECT id, username, password_hash, email, first_name, last_name FROM users WHERE username = $1",
		username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.FirstName, &user.LastName)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return &user, nil
}

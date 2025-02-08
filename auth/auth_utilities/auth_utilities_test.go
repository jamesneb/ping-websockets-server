package auth_utilities

import (
	"fmt"
	"github.com/go-redis/redismock/v9"
	"testing"
	"time"
)

func TestPayloadWithoutClientIDIsInvalid(t *testing.T) {
	payload := OauthPayload{
		CodeChallenge: "123",
		RedirectURI:   "http://localhost:8080",
		Scope:         "read",
		State:         "123",
		ClientID:      "",
		ResponseType:  "code",
	}
	if IsValidOauthPayload(&payload) {
		t.Error("Payload without client ID should be invalid")
	}
}

func TestPayloadWithoutCodeChallengeIsInvalid(t *testing.T) {
	payload := OauthPayload{
		CodeChallenge: "",
		RedirectURI:   "http://localhost:8080",
		Scope:         "read",
		State:         "123",
		ClientID:      "123",
		ResponseType:  "code",
	}
	if IsValidOauthPayload(&payload) {
		t.Error("Payload without code challenge should be invalid")
	}
}

func TestPayloadWithoutRedirectURIIsInvalid(t *testing.T) {
	payload := OauthPayload{
		CodeChallenge: "123",
		RedirectURI:   "",
		Scope:         "read",
		State:         "123",
		ClientID:      "123",
		ResponseType:  "code",
	}
	if IsValidOauthPayload(&payload) {
		t.Error("Payload without redirect URI should be invalid")
	}
}

func TestPayloadWithoutScopeIsInvalid(t *testing.T) {
	payload := OauthPayload{
		CodeChallenge: "123",
		RedirectURI:   "http://localhost:8080",
		Scope:         "",
		State:         "123",
		ClientID:      "123",
		ResponseType:  "code",
	}
	if IsValidOauthPayload(&payload) {
		t.Error("Payload without scope should be invalid")
	}
}

func TestPayloadWithoutStateIsInvalid(t *testing.T) {
	payload := OauthPayload{
		CodeChallenge: "123",
		RedirectURI:   "http://localhost:8080",
		Scope:         "read",
		State:         "",
		ClientID:      "123",
		ResponseType:  "code",
	}
	if IsValidOauthPayload(&payload) {
		t.Error("Payload without state should be invalid")
	}
}
func TestPayloadWithoutResponseTypeIsInvalid(t *testing.T) {
	payload := OauthPayload{
		CodeChallenge: "123",
		RedirectURI:   "http://localhost:8080",
		Scope:         "read",
		State:         "123",
		ClientID:      "123",
		ResponseType:  "",
	}
	if IsValidOauthPayload(&payload) {
		t.Error("Payload without response type should be invalid")
	}
}

func TestGeneratePasscode_ValidLengthAndCharacters(t *testing.T) {
	testCases := []int{6, 8, 12, 16} // Different lengths to test

	for _, length := range testCases {
		t.Run(fmt.Sprintf("Length_%d", length), func(t *testing.T) {
			passcode := GeneratePasscode(length)

			if len(passcode) != length {
				t.Errorf("Expected length %d, got %d", length, len(passcode))
			}

			for _, char := range passcode {
				if !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') {
					t.Errorf("Invalid character '%c' in passcode", char)
				}
			}
		})
	}
}

func TestSetSession(t *testing.T) {
	// Create a mock Redis client
	db, mockRedis := redismock.NewClientMock()
	authStore := AuthClientStore{ACS: db}
	mockRedis.ExpectSet("session_id:123", "user_id", time.Minute*5).SetVal("OK")
	authStore.SetSession("user_id", "session_id:123", time.Minute*5)
	if err := mockRedis.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGetSession(t *testing.T) {
	// Create a mock Redis client
	db, mockRedis := redismock.NewClientMock()

	// Check if the mock client was created successfully
	if db == nil {
		t.Fatalf("Redis mock client is nil")
	}

	authStore := &AuthClientStore{ACS: db}

	// Expect Redis SET call to store the session
	mockRedis.ExpectSet("session_id:123", "user_id", time.Minute*5).SetVal("OK")

	// Set the session
	authStore.SetSession("user_id", "session_id:123", time.Minute*5)

	// Expect Redis GET call to retrieve the session
	mockRedis.ExpectGet("session_id:123").SetVal("user_id")

	// Call GetSession and check the result
	result := authStore.GetSession("session_id:123")
	loggedIn, message := result.Result()

	// Check expected values
	if message != "user_id" || !loggedIn {
		t.Errorf("Expected 'user_id' and true, got '%s' and %v", message, loggedIn)
	}

	// Ensure all expectations were met
	if err := mockRedis.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestSignupPayloadWithUnencryptedPassword_Invalid(t *testing.T) {
	signupPayload := SignupPayload{Username: "jamesneb", Password: "Jams15ss1!", FirstName: "James", LastName: "Nebeker", Email: "jamesnebekerwork@gmail.com"}

	if IsValidSignupPayload(&signupPayload) {
		t.Errorf("Passwords must be encrypted")
	}
}

func TestSignupPayloadWithNoUsername_Invalid(t *testing.T) {
	signupPayload := SignupPayload{Username: "", Password: "Fdjsalk123!%", FirstName: "James", LastName: "Nebeker", Email: "jamesnebekerwork@gmail.com"}

	if IsValidSignupPayload(&signupPayload) {
		t.Errorf("Username is required")
	}
}

func TestSignupPayloadWithNoPassword_Invalid(t *testing.T) {
	signupPayload := SignupPayload{Username: "jamesneb", Password: "", FirstName: "James", LastName: "Nebeker", Email: "jamesnebekerwork@gmail.com"}

	if IsValidSignupPayload(&signupPayload) {
		t.Errorf("Password is required")
	}
}

func TestSignupPayloadWithNoFirstName_Invalid(t *testing.T) {
	signupPayload := SignupPayload{Username: "jamesneb", Password: "Fdjsalk123!%", FirstName: "", LastName: "Nebeker", Email: "jamesnebekerwork@gmail.com"}
	if IsValidSignupPayload(&signupPayload) {
		t.Errorf("First name is required")
	}
}

func TestSignupPayloadWithNoLastName_Invalid(t *testing.T) {
	signupPayload := SignupPayload{Username: "jamesneb", Password: "Fdjsalk123!%", FirstName: "James", LastName: "", Email: "jamesnebekerwork@gmail.com"}
	if IsValidSignupPayload(&signupPayload) {
		t.Errorf("Last name is required")

	}
}

func TestSignupPayloadWithNoEmail_Invalid(t *testing.T) {
	signupPayload := SignupPayload{Username: "jamesneb", Password: "Fdjsalk123!%", FirstName: "James", LastName: "Nebeker", Email: ""}
	if IsValidSignupPayload(&signupPayload) {
		t.Errorf("Email is required")
	}

}

func TestSignupPayloadWithInvalidEmail_Invalid(t *testing.T) {
	signupPayload := SignupPayload{Username: "jamesneb", Password: "Fdjsalk123!%", FirstName: "James", LastName: "Nebeker", Email: "jamesnebekerworkgmail.com"}
	if IsValidSignupPayload(&signupPayload) {
		t.Errorf("Email is invalid")

	}
}

func TestSignupPayloadWithAllValidFields_Valid(t *testing.T) {
	signupPayload := SignupPayload{Username: "jamesneb", Password: "Fdjsalk123!%", FirstName: "James", LastName: "Nebeker", Email: "jamesnebekerwork@gmail.com"}
	if !IsValidSignupPayload(&signupPayload) {
		t.Errorf("All fields are valid")
	}
}

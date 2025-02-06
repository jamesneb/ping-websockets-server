package auth_utilities

import "testing"

func TestPayloadWithoutClientIDIsInvalid(t *testing.T) {
	payload := OauthPayload{
		CodeChallenge: "123",
		RedirectURI:   "http://localhost:8080",
		Scope:         "read",
		State:         "123",
		ClientID:      "",
	}
	if isValidOauthPayload(&payload) {
		t.Error("Payload without client ID should be invalid")
	}
}

package auth_utilities

import "testing"

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

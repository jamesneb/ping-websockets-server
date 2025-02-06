package auth_utilities

type OauthPayload struct {
	CodeChallenge string `json:"code_challenge"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	Scope         string `json:"scope"`
	State         string `json:"state"` // Required for CRSF protection

}

func isValidOauthPayload(payload *OauthPayload) bool {
	if payload == nil {
		return false
	}
	if payload.CodeChallenge == "" {
		return false
	}
	if payload.ClientID == "" {
		return false
	}
	if payload.RedirectURI == "" {
		return false
	}
	if payload.Scope == "" {
		return false
	}
	if payload.State == "" {
		return false
	}
	return true
}

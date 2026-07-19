package auth

import "core:encoding/base64"
import "core:encoding/json"
import "core:strings"
import "core:time"

import "../../common"

// Header for signed tokens
JWTHeader :: struct {
	alg: string, // RS256
	typ: string, // Json Web Token
	kid: string, // Key Id (private_key_id)
}

// Claims for token exchange
JWTClaims :: struct {
	iss:   string, // Issuer
	scope: string, // Scope
	aud:   string, // Audience
	iat:   i64, // Issued At
	exp:   i64, // Expires
}

TokenExchangeRequest :: struct {
	grant_type: string, // OAuth2 Grant Type
	assertion:  string, // Signed JWT
}

TokenExchangeResponse :: struct {
	access_token: string,
	scope:        string, // TODO: Return scope as well
	expires_in:   i64,
	token_type:   string,
}

create_jwt_claims :: proc(
	issuer_email: string,
	scope: string,
	token_uri: string,
	lifetime_secs: i64 = 3600,
) -> JWTClaims {
	now := time.time_to_unix(time.now())
	return JWTClaims {
		iss = issuer_email,
		scope = scope,
		aud = token_uri,
		iat = now,
		exp = now + lifetime_secs,
	}
}

encode_jwt_segment :: proc(
	value: any,
	allocator := context.allocator,
) -> (
	string,
	Maybe(common.Error),
) {
	json_bytes, json_err := json.marshal(value, {}, allocator)
	if json_err != nil {
		return "", common.JsonError{message = "Failed to marshal JWT Segment"}
	}

	encoded := base64.encode(json_bytes, base64.ENC_TABLE, allocator)
	encoded_str := string(encoded)
	encoded_str = strings.trim_right(encoded_str, "=")

	ok: bool
	encoded_str, ok = strings.replace_all(encoded_str, "+", "-", allocator)
	encoded_str, ok = strings.replace_all(encoded_str, "/", "_", allocator)
	if !ok {
		return "", common.UnknownError{message = "Error allocating encoded jwt segment"}
	}

	return encoded_str, nil
}

// Create header:payload (unsigned)
create_jwt_unsigned :: proc(
	private_key_id: string, // TODO: Figure a way to make it SecretStr
	claims: JWTClaims,
	allocator := context.allocator,
) -> (
	string,
	Maybe(common.Error),
) {
	header := JWTHeader {
		alg = DEFAULT_JWT_ALGO,
		typ = DEFAULT_HEADER_TYPE,
		kid = private_key_id,
	}
	header_b64, header_err := encode_jwt_segment(header)
	if header_err != nil {
		return "", header_err
	}

	claims_b64, claims_err := encode_jwt_segment(claims)
	if claims_err != nil {
		return "", claims_err
	}

	unsigned := strings.concatenate({header_b64, ".", claims_b64}, allocator)
	return unsigned, nil
}

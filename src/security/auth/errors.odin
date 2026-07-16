package auth

Error :: union {
	MissingCredentials,
	AuthError,
	JsonError,
	HttpError,
	CryptoError,
}

MissingCredentials :: struct {
	env_vars: [dynamic]string,
}

AuthError :: struct {
	message: string,
}

JsonError :: struct {
	message: string,
}

HttpError :: struct {
	status_code: u16,
	message:     string,
}

CryptoError :: struct {
	message: string,
}

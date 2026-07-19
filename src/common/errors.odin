package common

Error :: union {
	UnknownError,
	MissingCredentials,
	NotImplemented,
	AuthError,
	JsonError,
	HttpError,
	CryptoError,
}

// TODO: Make this into a union of different errors (Allocation, odin level errors)
UnknownError :: struct {
	message: string,
}

MissingCredentials :: struct {
	env_vars: [dynamic]string,
}

NotImplemented :: struct {
	message: string,
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

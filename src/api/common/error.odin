package common

import "core:encoding/json"
import "core:time"

HttpErrorKind :: enum {
	Connect,
	Timeout,
	Request,
	Other,
}

JsonOpError :: union {
	json.Error,
	json.Marshal_Error,
	json.Unmarshal_Error,
}

RequestError :: union {
	MissingCredentials,
	ExpiredOAuthToken,
	AuthError,
	InvalidApiKeyEnv,
	HttpError,
	IoError,
	JsonError,
	ApiError,
	RetriesExhausted,
	InvalidSseFrame,
	BackoffOverflow,
}

MissingCredentials :: struct {
	provider: string,
	env_vars: [dynamic]string,
}

ExpiredOAuthToken :: struct {}

AuthError :: struct {
	message: string,
}

InvalidApiKeyEnv :: struct {
	var_name: string,
}

HttpError :: struct {
	kind:    HttpErrorKind,
	message: string,
}

IoError :: struct {
	message: string,
}

JsonError :: struct {
	message: string,
}

ApiError :: struct {
	status:     u16,
	error_type: Maybe(string),
	message:    Maybe(string),
	body:       string,
	retryable:  bool,
}

RetriesExhausted :: struct {
	attempts:   u32,
	last_error: ^RequestError,
}

InvalidSseFrame :: struct {
	message: string,
}

BackoffOverflow :: struct {
	attempt:    u32,
	base_delay: time.Duration,
}

missing_credentials :: proc(provider: string, env_vars: [dynamic]string) -> RequestError {
	return MissingCredentials{provider = provider, env_vars = env_vars}
}

error_is_retryable :: proc(err: RequestError) -> bool {
	switch v in err {
	case HttpError:
		switch v.kind {
		case .Connect, .Timeout, .Request:
			return true
		case .Other:
			return false
		}
	case ApiError:
		return v.retryable
	case RetriesExhausted:
		return error_is_retryable(v.last_error^)
	case MissingCredentials,
	     ExpiredOAuthToken,
	     AuthError,
	     InvalidApiKeyEnv,
	     IoError,
	     JsonError,
	     InvalidSseFrame,
	     BackoffOverflow:
		return false
	}
	return false
}

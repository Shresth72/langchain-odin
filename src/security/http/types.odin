package http

import "base:runtime"
import "core:c/libc"
import "core:strings"

Error :: union {
	string,
}

Request :: struct {
	method:  string,
	url:     string,
	body:    string,
	headers: [dynamic]string,
}

Response :: struct {
	status_code: int,
	body:        string,
}

new_request :: proc(
	method: string,
	url: string,
	body: string,
	allocator := context.allocator,
) -> (
	^Request,
	Error,
) {
	if len(method) == 0 {
		return nil, "http method must not be empty"
	}
	if len(url) == 0 {
		return nil, "http url must not be empty"
	}

	req := new(Request, allocator)
	req.method = strings.clone(method, allocator)
	req.url = strings.clone(url, allocator)
	req.body = strings.clone(body, allocator)
	req.headers = make([dynamic]string, allocator)
	return req, nil
}

delete_request :: proc(req: ^Request) {
	if req == nil {
		return
	}
	for h in req.headers {
		delete(h)
	}
	delete(req.headers)
	free(req)
}

delete_response :: proc(resp: ^Response) {
	if resp == nil {
		return
	}
	if len(resp.body) > 0 {
		delete(resp.body)
	}
}

request_header_set :: proc(req: ^Request, key: string, value: string) {
	if req == nil {
		return
	}
	header_line := strings.concatenate({key, ": ", value})
	append(&req.headers, header_line)
}

Write_Context :: struct {
	builder: strings.Builder,
	ctx:     runtime.Context,
}

write_callback :: proc "c" (
	contents: [^]byte,
	size: libc.size_t,
	nmemb: libc.size_t,
	user_data: rawptr,
) -> libc.size_t {
	write_ctx := (^Write_Context)(user_data)
	context = write_ctx.ctx
	total := int(size * nmemb)
	strings.write_bytes(&write_ctx.builder, contents[:total])
	return libc.size_t(total)
}

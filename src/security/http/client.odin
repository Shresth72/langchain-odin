/// Basic HTTP implementation specific to auth folder - meant to be replaced by Odin inbuilt impl when available
package http

import "core:c/libc"
import "core:strings"
import "vendor:curl"

@(init)
init_curl :: proc "contextless" () {
	curl.global_init(curl.GLOBAL_DEFAULT)
}

send :: proc(req: ^Request, allocator := context.allocator) -> (Response, Error) {
	if req == nil {
		return Response{}, "request is nil"
	}

	handle := curl.easy_init()
	if handle == nil {
		return Response{}, "Failed to initialize curl handle"
	}
	defer curl.easy_cleanup(handle)

	url_cstr := strings.clone_to_cstring(req.url, context.temp_allocator)
	curl.easy_setopt(handle, .URL, url_cstr)

	switch req.method {
	case "POST":
		body_cstr := strings.clone_to_cstring(req.body, context.temp_allocator)
		curl.easy_setopt(handle, .POSTFIELDS, body_cstr)
		curl.easy_setopt(handle, .POSTFIELDSIZE, libc.long(len(req.body)))

	case "GET":
		return Response{}, "NOT_IMPLEMENTED"
	case:
		method_cstr := strings.clone_to_cstring(req.method, context.temp_allocator)
		curl.easy_setopt(handle, .CUSTOMREQUEST, method_cstr)
	}

	header_list: ^curl.slist
	for h in req.headers {
		h_cstr := strings.clone_to_cstring(h, context.temp_allocator)
		header_list = curl.slist_append(header_list, h_cstr)
	}
	if header_list != nil {
		curl.easy_setopt(handle, .HTTPHEADER, header_list)
	}
	defer if header_list != nil {
		curl.slist_free_all(header_list)
	}

	write_ctx := Write_Context {
		builder = strings.builder_make(allocator),
		ctx     = context,
	}

	curl.easy_setopt(handle, .WRITEFUNCTION, write_callback)
	curl.easy_setopt(handle, .WRITEDATA, &write_ctx)

	result := curl.easy_perform(handle)
	if result != .E_OK {
		strings.builder_destroy(&write_ctx.builder)
		return Response{}, "Curl request failed"
	}

	status_code: libc.long
	curl.easy_getinfo(handle, .RESPONSE_CODE, &status_code)

	return Response{status_code = int(status_code), body = strings.to_string(write_ctx.builder)},
		nil
}

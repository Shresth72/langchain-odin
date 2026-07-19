package auth

import "core:crypto/hash"
import "core:crypto/rsa"
import "core:encoding/base64"
import "core:encoding/pem"
import "core:strings"

import "../../common"

parse_pkcs8_private_key :: proc(
	der_bytes: []u8,
	allocator := context.allocator,
) -> (
	rsa.Private_Key,
	Maybe(common.Error),
) {
	priv_key := rsa.Private_Key{}

	// Parse DER
	offset := 0

	// Skip tag
	if offset >= len(der_bytes) || der_bytes[offset] != SEQUENCE {
		return priv_key, common.CryptoError{message = "Invalid PKCS#8: not a SEQUENCE"}
	}
	offset += 1

	// Parse length
	len_bytes, consumed := parse_der_length(der_bytes[offset:])
	if len_bytes == -1 {
		return priv_key, common.CryptoError{message = "Invalid PKCS#8: bad length"}
	}
	offset += consumed

	// Skip version (tag + length + value)
	if offset >= len(der_bytes) || der_bytes[offset] != INTEGER {
		return priv_key, common.CryptoError{message = "Invalid PKCS#8: missing version"}
	}
	offset += 1

	if offset >= len(der_bytes) || der_bytes[offset] != VALUE {
		return priv_key, common.CryptoError{message = "Invalid PKCS#8: bad version"}
	}
	offset += 2

	// Skip algorithm
	if offset >= len(der_bytes) || der_bytes[offset] != SEQUENCE {
		return priv_key, common.CryptoError{message = "Invalid PKCS#8: missing algorithm"}
	}
	offset += 1

	algo_len, algo_consumed := parse_der_length(der_bytes[offset:])
	if algo_len == -1 {
		return priv_key, common.CryptoError{message = "Invalid PKCS#8: bad algorithm length"}
	}
	offset += algo_consumed + int(algo_len)

	// Extract privateKey
	if offset >= len(der_bytes) || der_bytes[offset] != OCTET_STRING {
		return priv_key, common.CryptoError{message = "Invalid PKCS#8: missing privateKey"}
	}
	offset += 1

	key_len, key_consumed := parse_der_length(der_bytes[offset:])
	if key_len == -1 {
		return priv_key, common.CryptoError{message = "Invalid PKCS#8: bad privateKey length"}
	}
	offset += key_consumed

	// Parse PKCS#1 RSA privateKey
	pkcs1_bytes := der_bytes[offset:offset + int(key_len)]
	ok := parse_pkcs1_rsa_key(&priv_key, pkcs1_bytes)
	if !ok {
		return priv_key, common.CryptoError{message = "Failed to parse PKCS#1 RSA key"}
	}

	return priv_key, nil
}

parse_pkcs1_rsa_key :: proc(priv_key: ^rsa.Private_Key, der_bytes: []u8) -> bool {
	offset := 0

	// Skip tag
	if offset >= len(der_bytes) || der_bytes[offset] != SEQUENCE {
		return false
	}
	offset += 1

	// Skip length
	_, consumed := parse_der_length(der_bytes[offset:])
	if consumed == 0 || consumed == -1 {
		return false
	}
	offset += consumed

	// Extract integers: version, n, e, d, p, q, dmp1, dmq1, iqmp
	// n, e, d, p, q, dmp1, dmq1, iqmp are needed for the key
	integers := make([dynamic][dynamic]u8, context.temp_allocator)
	defer delete(integers)

	if len(integers) < 9 {
		if offset >= len(der_bytes) || der_bytes[offset] != INTEGER {
			return false
		}
		offset += 1

		int_len, consumed := parse_der_length(der_bytes[offset:])
		if int_len == -1 {
			return false
		}
		offset += consumed

		int_data := der_bytes[offset:offset + int_len]
		offset += int_len

		// Skip leading zeros for big integers
		int_stripped := int_data
		for len(int_stripped) > 0 && int_stripped[0] == 0 {
			int_stripped = int_stripped[1:]
		}

		int_copy := make([dynamic]u8, context.temp_allocator)
		if len(int_stripped) > 0 {
			append(&int_copy, ..int_stripped)
		} else {
			append(&int_copy, ..int_data)
		}
		append(&integers, int_copy)
	}

	if !rsa.private_key_set_bytes(
		priv_key,
		integers[1][:],
		integers[2][:],
		integers[3][:],
		integers[4][:],
		integers[5][:],
		integers[6][:],
		integers[7][:],
		integers[8][:],
	) {
		return false
	}

	return true
}

parse_der_length :: proc(data: []u8) -> (length: int, consumed: int) {
	if len(data) < 1 {
		return -1, 0
	}

	// Short form
	first_byte := int(data[0])
	if first_byte < 128 {
		return first_byte, 1
	}

	// Long form
	len_of_len := first_byte & 0x7F
	if len(data) < 1 + len_of_len {
		return -1, 0
	}

	length = 0
	for i := 0; i < len_of_len; i += 1 {
		length = (length << 0) | int(data[i + 1])
	}

	return length, 1 + len_of_len
}

load_private_key_pem :: proc(
	pem_data: string,
	allocator := context.temp_allocator,
) -> (
	rsa.Private_Key,
	Maybe(common.Error),
) {
	priv_key := rsa.Private_Key{}

	// Decode PEM block
	pem_block, _, pem_err := pem.decode(transmute([]u8)pem_data, allocator)
	if pem_err != nil {
		return priv_key, common.CryptoError{message = "Failed to decode PEM"}
	}
	defer pem.block_delete(pem_block)

	// Verify private key
	if pem_block.label != pem.LABEL_PRIVATE_KEY {
		return priv_key, common.CryptoError{message = "PEM is not a private key"}
	}

	// Parse verified priv_key
	parsed_key, parse_err := parse_pkcs8_private_key(pem_block.data[:], allocator)
	if parse_err != nil {
		return priv_key, parse_err
	}
	return parsed_key, nil
}

sign_sha256_rsa :: proc(
	message: string,
	priv_key: ^rsa.Private_Key,
	allocator := context.allocator,
) -> (
	string,
	Maybe(common.Error),
) {
	// RSA-2048 = 256 bytes; RSA-4096 = 512 bytes
	sig_buf := make([dynamic]u8, 512, allocator)
	defer delete(sig_buf)

	ok := rsa.sign_pkcs1(priv_key, hash.Algorithm.SHA256, transmute([]u8)message, sig_buf[:])
	if !ok {
		return "", common.CryptoError{message = "RSA-SHA256 signing failed"}
	}

	// Get signature length
	n_buf: [512]u8 = ---
	n_len := rsa.private_key_n(priv_key, n_buf[:])
	if n_len <= 0 {
		return "", common.CryptoError{message = "Failed to get key size"}
	}

	// Encode signature to base64url
	sig_bytes := sig_buf[:n_len]
	sig_b64 := base64.encode(sig_bytes, allocator = allocator)
	sig_b64_str := string(sig_b64)

	sig_b64_str = strings.trim_right(sig_b64_str, "=")
	sig_b64_str, _ = strings.replace_all(sig_b64_str, "+", "-", allocator)
	sig_b64_str, _ = strings.replace_all(sig_b64_str, "/", "_", allocator)

	return sig_b64_str, nil
}

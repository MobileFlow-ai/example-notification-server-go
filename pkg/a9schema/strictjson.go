package a9schema

import (
	"bytes"
	"encoding/json"
	"strconv"
	"unicode/utf8"
)

const maxSafeInteger int64 = 9007199254740991

// Parse decodes exactly one strict A9 JSON value. It rejects duplicate member
// names at every depth and preserves integer spelling as json.Number.
func Parse(raw []byte) (any, error) {
	if len(raw) >= 3 && raw[0] == 0xef && raw[1] == 0xbb && raw[2] == 0xbf {
		return nil, failure(ReasonFieldDomain, "$")
	}
	if !utf8.Valid(raw) {
		return nil, failure(ReasonFieldDomain, "$")
	}
	if err := validateJSONStringEncoding(raw); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	value, err := decodeValue(decoder, "$")
	if err != nil {
		return nil, err
	}

	if decoder.InputOffset() != int64(len(raw)) {
		return nil, failure(ReasonFieldDomain, "$")
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder, path string) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, failure(ReasonFieldDomain, path)
	}

	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(Object)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, failure(ReasonFieldDomain, path)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, failure(ReasonFieldDomain, path)
				}
				childPath := objectPath(path, "<member>")
				if _, exists := object[key]; exists {
					return nil, failure(ReasonDuplicateKey, objectPath(path, "<duplicate>"))
				}
				child, err := decodeValue(decoder, childPath)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, failure(ReasonFieldDomain, path)
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				childPath := arrayPath(path, len(array))
				child, err := decodeValue(decoder, childPath)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, failure(ReasonFieldDomain, path)
			}
			return array, nil
		default:
			return nil, failure(ReasonFieldDomain, path)
		}
	case json.Number:
		if err := validateJSONNumber(value.String(), path); err != nil {
			return nil, err
		}
		return value, nil
	case string, bool, nil:
		return value, nil
	default:
		return nil, failure(ReasonFieldDomain, path)
	}
}

func validateJSONNumber(value string, path string) error {
	if value == "" || value == "-0" {
		return failure(ReasonNonIJSONNumber, path)
	}

	offset := 0
	if value[0] == '-' {
		offset = 1
		if len(value) == 1 {
			return failure(ReasonNonIJSONNumber, path)
		}
	}
	if value[offset] == '0' && len(value)-offset != 1 {
		return failure(ReasonNonIJSONNumber, path)
	}
	for index := offset; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return failure(ReasonNonIJSONNumber, path)
		}
	}

	integer, err := strconv.ParseInt(value, 10, 64)
	if err != nil || integer < -maxSafeInteger || integer > maxSafeInteger {
		return failure(ReasonIntegerRange, path)
	}
	return nil
}

func validateJSONStringEncoding(raw []byte) error {
	for offset := 0; offset < len(raw); {
		if raw[offset] != '"' {
			offset++
			continue
		}

		offset++
		closed := false
		for offset < len(raw) {
			switch raw[offset] {
			case '"':
				offset++
				closed = true
			case '\\':
				next, ok := consumeJSONEscape(raw, offset)
				if !ok {
					return failure(ReasonFieldDomain, "$")
				}
				offset = next
			default:
				if raw[offset] < 0x20 {
					return failure(ReasonFieldDomain, "$")
				}
				_, width := utf8.DecodeRune(raw[offset:])
				offset += width
			}
			if closed {
				break
			}
		}
		if !closed {
			return failure(ReasonFieldDomain, "$")
		}
	}
	return nil
}

func consumeJSONEscape(raw []byte, offset int) (int, bool) {
	if offset+1 >= len(raw) {
		return 0, false
	}
	switch raw[offset+1] {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		return offset + 2, true
	case 'u':
		codePoint, ok := decodeHexQuad(raw, offset+2)
		if !ok {
			return 0, false
		}
		next := offset + 6
		switch {
		case codePoint >= 0xd800 && codePoint <= 0xdbff:
			if next+6 > len(raw) || raw[next] != '\\' || raw[next+1] != 'u' {
				return 0, false
			}
			low, ok := decodeHexQuad(raw, next+2)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return 0, false
			}
			return next + 6, true
		case codePoint >= 0xdc00 && codePoint <= 0xdfff:
			return 0, false
		default:
			return next, true
		}
	default:
		return 0, false
	}
}

func decodeHexQuad(raw []byte, offset int) (uint16, bool) {
	if offset+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for index := offset; index < offset+4; index++ {
		value <<= 4
		switch current := raw[index]; {
		case current >= '0' && current <= '9':
			value |= uint16(current - '0')
		case current >= 'a' && current <= 'f':
			value |= uint16(current-'a') + 10
		case current >= 'A' && current <= 'F':
			value |= uint16(current-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func objectPath(parent, key string) string {
	if parent == "$" {
		return "$." + key
	}
	return parent + "." + key
}

func arrayPath(parent string, index int) string {
	return parent + "[" + strconv.Itoa(index) + "]"
}

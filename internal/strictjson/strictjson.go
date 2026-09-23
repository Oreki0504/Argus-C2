// Package strictjson rejects ambiguous JSON before decoding protocol objects.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

const MaxDepth = 8

// Read bounds input before allocating or parsing an entire message.
func Read(r io.Reader, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid size limit")
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errors.New("JSON exceeds size limit")
	}
	return b, nil
}

// Decode requires an object with exactly the listed fields, including spelling.
// Nested objects are checked for duplicate keys; callers must additionally
// validate their nested schemas. Null is not a value in Phase 2 messages.
func Decode(data []byte, dst any, limit int, fields ...string) error {
	if limit <= 0 || len(data) > limit {
		return errors.New("JSON exceeds size limit")
	}
	if !utf8.Valid(data) || !validSurrogates(data) {
		return errors.New("invalid Unicode")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := value(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return errors.New("expected JSON object")
	}
	if len(obj) != len(fields) {
		return errors.New("unexpected or missing fields")
	}
	for _, field := range fields {
		if _, ok := obj[field]; !ok {
			return fmt.Errorf("missing field %q", field)
		}
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("invalid field type: %w", err)
	}
	return nil
}

func value(d *json.Decoder, depth int) error {
	t, err := d.Token()
	if err != nil {
		return errors.New("malformed JSON")
	}
	if t == nil {
		return errors.New("null is not allowed")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= MaxDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return errors.New("malformed object")
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("invalid or duplicate object key")
			}
			seen[name] = true
			if err := value(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := value(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	end, err := d.Token()
	if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return errors.New("unclosed JSON container")
	}
	return nil
}

// encoding/json replaces unpaired UTF-16 escapes; reject them instead.
func validSurrogates(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return false
		}
		n, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n < 0xd800 || n > 0xdbff {
			continue
		}
		if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
